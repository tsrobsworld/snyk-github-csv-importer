#!/usr/bin/env python3
"""
Snyk Repository Importer

This script imports GitHub repositories into Snyk with the following options:
1. Import into an existing organization (recommended)
2. Create new organizations for each repository (requires org creation permissions)

Usage:
    # Import into existing organization (recommended)
    python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --org-id ORG_ID --csv-file repos.csv
    
    # Create new organizations for each repo (requires permissions)
    python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --create-orgs
"""

import json
import argparse
import sys
import os
import csv
import requests
import re
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from dataclasses import dataclass
from queue import Queue
import signal


@dataclass
class RepoInfo:
    """Data class to hold repository information."""
    url: str
    owner: str
    repo: str
    import_status: str = "pending"
    error_message: Optional[str] = None


class RateLimiter:
    """Rate limiter to control API call frequency."""
    
    def __init__(self, calls_per_second: float = 5.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        with self.lock:
            current_time = time.time()
            time_since_last_call = current_time - self.last_call_time
            
            if time_since_last_call < self.min_interval:
                sleep_time = self.min_interval - time_since_last_call
                time.sleep(sleep_time)
            
            self.last_call_time = time.time()


class SnykRepoImporter:
    """Snyk repository importer with support for both existing and new organizations."""

    def __init__(self, token: str, org_id: str = None, group_id: str = None,
                 region: str = "SNYK-US-01", rate_limit: float = 20.0, max_threads: int = 10,
                 create_orgs: bool = False, integration_type: str = "github", source_org_id: str = None,
                 org_naming: str = "owner-repo", org_chunk_size: int = 20, import_chunk_size: int = 20):
        self.token = token
        self.org_id = org_id
        self.group_id = group_id
        self.create_orgs = create_orgs
        self.integration_type = integration_type
        self.source_org_id = source_org_id
        self.org_naming = org_naming
        self.org_chunk_size = org_chunk_size
        self.import_chunk_size = import_chunk_size
        self.base_url = self._get_base_url(region)
        self.snyk_rate_limiter = RateLimiter(rate_limit)  # Snyk API rate limiter (configurable)
        self.github_rate_limiter = RateLimiter(1.0)  # GitHub API rate limiter (1 call/sec for safety)
        self.rate_limit = rate_limit
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Accept': '*/*',
            'Content-Type': 'application/json'
        })
        
        # Thread-safe logging
        self.logger = self._setup_logging()
        self.results = []
        self.results_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_repos': 0,
            'processed': 0,
            'successful_imports': 0,
            'failed_imports': 0,
            'orgs_created': 0,
            'orgs_existing': 0
        }
        self.stats_lock = threading.Lock()
        
        # Integration ID cache
        self.integration_ids = {}
        # Existing organizations cache
        self.existing_orgs = {}
        
        # Validate configuration
        if not create_orgs and not org_id:
            raise ValueError("Either org_id must be provided for existing org mode, or create_orgs=True with group_id")
        if create_orgs and not group_id:
            raise ValueError("group_id must be provided when create_orgs=True")
        
        # Validate rate limits
        if rate_limit > 27.0:
            raise ValueError("Snyk API rate limit cannot exceed 27 calls per second (1,620 per minute)")
        if rate_limit <= 0:
            raise ValueError("Rate limit must be positive")

    def _get_base_url(self, region: str) -> str:
        """Get the appropriate API base URL for the region."""
        region_urls = {
            "SNYK-US-01": "https://api.snyk.io",
            "SNYK-US-02": "https://api.us.snyk.io",
            "SNYK-EU-01": "https://api.eu.snyk.io",
            "SNYK-AU-01": "https://api.au.snyk.io"
        }
        return region_urls.get(region, "https://api.snyk.io")
    
    def _make_github_api_call(self, url: str, headers: dict = None) -> requests.Response:
        """Make a GitHub API call with proper rate limiting."""
        self.github_rate_limiter.wait()
        
        if headers is None:
            headers = {}
        
        # Add GitHub API headers
        github_headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SnykRepoImporter/1.0'
        }
        github_headers.update(headers)
        
        return self.session.get(url, headers=github_headers)
    
    def _make_snyk_api_call(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make a Snyk API call with proper rate limiting and retry logic."""
        self.snyk_rate_limiter.wait()
        
        if method.upper() == 'GET':
            response = self.session.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = self.session.post(url, **kwargs)
        elif method.upper() == 'PUT':
            response = self.session.put(url, **kwargs)
        elif method.upper() == 'DELETE':
            response = self.session.delete(url, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        # Handle rate limiting (429 responses)
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After', '60')
            try:
                wait_time = int(retry_after)
            except ValueError:
                wait_time = 60  # Default to 60 seconds if header is invalid
            
            self.logger.warning(f"Rate limited by Snyk API. Waiting {wait_time} seconds before retry...")
            time.sleep(wait_time)
            
            # Retry the request once
            if method.upper() == 'GET':
                response = self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = self.session.post(url, **kwargs)
            elif method.upper() == 'PUT':
                response = self.session.put(url, **kwargs)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, **kwargs)
        
        return response

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('snyk_importer_existing_org')
        logger.setLevel(logging.INFO)
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler(f'snyk_import_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger

    def parse_github_url(self, url: str) -> Tuple[str, str]:
        """Parse GitHub URL to extract owner and repository name."""
        # Remove @ symbol if present
        url = url.lstrip('@')
        
        # Handle different GitHub URL formats
        patterns = [
            r'https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
            r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$',
            r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, url)
            if match:
                owner, repo = match.groups()
                # Remove .git suffix if present
                repo = repo.rstrip('.git')
                return owner, repo
        
        raise ValueError(f"Invalid GitHub URL format: {url}")

    def read_csv_file(self, csv_file: str) -> List[RepoInfo]:
        """Read CSV file and parse repository URLs."""
        repos = []
        
        try:
            with open(csv_file, 'r', newline='', encoding='utf-8') as file:
                reader = csv.reader(file)
                
                for row_num, row in enumerate(reader, 1):
                    if not row or not row[0].strip():
                        continue
                    
                    url = row[0].strip()
                    try:
                        owner, repo = self.parse_github_url(url)
                        
                        repo_info = RepoInfo(
                            url=url,
                            owner=owner,
                            repo=repo
                        )
                        repos.append(repo_info)
                        
                    except ValueError as e:
                        self.logger.error(f"Row {row_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            self.logger.error(f"CSV file not found: {csv_file}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error reading CSV file: {e}")
            sys.exit(1)
        
        self.stats['total_repos'] = len(repos)
        self.logger.info(f"Loaded {len(repos)} repositories from CSV file")
        return repos

    def get_organization_name(self, repo_info: RepoInfo) -> str:
        """Generate organization name based on naming preference."""
        if self.org_naming == "repo-only":
            return repo_info.repo
        else:  # "owner-repo"
            return f"{repo_info.owner}-{repo_info.repo}"

    def fetch_existing_organizations(self) -> None:
        """Fetch all existing organizations and cache them by name."""
        self.logger.info("Fetching existing Snyk organizations...")
        self.snyk_rate_limiter.wait()
        
        try:
            response = self._make_snyk_api_call('GET', f"{self.base_url}/v1/orgs")
            if response.status_code == 200:
                orgs_data = response.json()
                # Handle both list and dict responses
                if isinstance(orgs_data, dict) and 'orgs' in orgs_data:
                    orgs = orgs_data['orgs']
                elif isinstance(orgs_data, list):
                    orgs = orgs_data
                else:
                    orgs = []
                
                for org in orgs:
                    if isinstance(org, dict) and 'name' in org:
                        self.existing_orgs[org['name']] = org
                
                self.logger.info(f"Found {len(self.existing_orgs)} existing organizations")
            else:
                self.logger.error(f"Failed to fetch organizations: {response.status_code} - {response.text}")
        except Exception as e:
            self.logger.error(f"Exception fetching organizations: {e}")

    def organization_exists(self, org_name: str) -> Optional[dict]:
        """Check if organization exists and return its data."""
        return self.existing_orgs.get(org_name)

    def create_organization(self, repo_info: RepoInfo) -> Optional[str]:
        """Create a Snyk organization for the repository."""
        org_name = self.get_organization_name(repo_info)
        
        # Check if organization already exists
        existing_org = self.organization_exists(org_name)
        if existing_org:
            self.logger.info(f"Organization '{org_name}' already exists with ID: {existing_org.get('id')}")
            with self.stats_lock:
                self.stats['orgs_existing'] += 1
            return existing_org.get('id')
        
        self.snyk_rate_limiter.wait()
        
        org_data = {
            "name": org_name,
            "groupId": self.group_id
        }
        
        # Add sourceOrgId if provided
        if self.source_org_id:
            org_data["sourceOrgId"] = self.source_org_id
        
        try:
            response = self._make_snyk_api_call('POST',
                f"{self.base_url}/v1/org",
                json=org_data
            )
            
            if response.status_code == 201:
                org_response = response.json()
                org_id = org_response.get('id')
                self.logger.info(f"Created organization '{org_name}' with ID: {org_id}")
                with self.stats_lock:
                    self.stats['orgs_created'] += 1
                return org_id
            elif response.status_code == 409:
                # Organization already exists, try to find it
                self.logger.warning(f"Organization '{org_name}' already exists, attempting to find it")
                return self.find_organization_by_name(org_name)
            else:
                self.logger.error(f"Failed to create organization '{org_name}': {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Exception creating organization '{org_name}': {e}")
            return None

    def find_organization_by_name(self, org_name: str) -> Optional[str]:
        """Find an existing organization by name."""
        self.snyk_rate_limiter.wait()
        
        try:
            response = self._make_snyk_api_call('GET', f"{self.base_url}/v1/orgs")
            
            if response.status_code == 200:
                response_data = response.json()
                orgs = response_data.get('orgs', response_data) if isinstance(response_data, dict) else response_data
                
                for org in orgs:
                    if isinstance(org, dict) and org.get('name') == org_name:
                        org_id = org.get('id')
                        self.logger.info(f"Found existing organization '{org_name}' with ID: {org_id}")
                        with self.stats_lock:
                            self.stats['orgs_existing'] += 1
                        return org_id
                        
            self.logger.error(f"Organization '{org_name}' not found")
            return None
            
        except Exception as e:
            self.logger.error(f"Exception finding organization '{org_name}': {e}")
            return None

    def get_integration_id(self, org_id: str) -> Optional[str]:
        """Get the integration ID for the specified integration type."""
        if org_id in self.integration_ids:
            return self.integration_ids[org_id]
            
        self.snyk_rate_limiter.wait()
        
        try:
            response = self._make_snyk_api_call('GET', f"{self.base_url}/v1/org/{org_id}/integrations")
            
            if response.status_code == 200:
                integrations = response.json()
                integration_id = integrations.get(self.integration_type)
                
                if integration_id:
                    self.integration_ids[org_id] = integration_id
                    self.logger.info(f"Found {self.integration_type} integration ID: {integration_id}")
                    return integration_id
                else:
                    available_integrations = list(integrations.keys())
                    self.logger.error(f"Integration '{self.integration_type}' not found. Available: {available_integrations}")
                    return None
            else:
                self.logger.error(f"Failed to fetch integrations: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Exception fetching integration ID: {e}")
            return None

    def import_repository(self, repo_info: RepoInfo, org_id: str) -> bool:
        """Import a repository into Snyk."""
        # Get integration ID first
        integration_id = self.get_integration_id(org_id)
        if not integration_id:
            error_msg = f"Failed to get {self.integration_type} integration ID for org {org_id}"
            self.logger.error(error_msg)
            repo_info.import_status = "failed"
            repo_info.error_message = error_msg
            with self.stats_lock:
                self.stats['failed_imports'] += 1
            return False
        
        self.snyk_rate_limiter.wait()
        
        import_data = {
            "target": {
                "owner": repo_info.owner,
                "name": repo_info.repo,
                "branch": "main"  # Default branch, can be made configurable
            }
        }
        
        # Add sourceOrgId if provided (required for some integrations)
        if self.source_org_id:
            import_data["sourceOrgId"] = self.source_org_id
        
        try:
            response = self._make_snyk_api_call('POST',
                f"{self.base_url}/v1/org/{org_id}/integrations/{integration_id}/import",
                json=import_data
            )
            
            if response.status_code in [200, 201, 202]:
                self.logger.info(f"Successfully initiated import for {repo_info.owner}/{repo_info.repo}")
                repo_info.import_status = "success"
                with self.stats_lock:
                    self.stats['successful_imports'] += 1
                return True
            else:
                error_msg = f"Failed to import {repo_info.owner}/{repo_info.repo}: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                repo_info.import_status = "failed"
                repo_info.error_message = error_msg
                with self.stats_lock:
                    self.stats['failed_imports'] += 1
                return False
                
        except Exception as e:
            error_msg = f"Exception importing {repo_info.owner}/{repo_info.repo}: {e}"
            self.logger.error(error_msg)
            repo_info.import_status = "failed"
            repo_info.error_message = error_msg
            with self.stats_lock:
                self.stats['failed_imports'] += 1
            return False

    def batch_create_organizations(self, repos: List[RepoInfo]) -> List[RepoInfo]:
        """Batch create organizations for all repositories with chunked processing."""
        self.logger.info("Phase 1: Creating organizations...")
        
        # First, fetch existing organizations
        self.fetch_existing_organizations()
        
        # Process repositories in chunks for better memory management and progress tracking
        chunk_size = min(self.org_chunk_size, len(repos))
        total_chunks = (len(repos) + chunk_size - 1) // chunk_size
        
        self.logger.info(f"Processing {len(repos)} repositories in {total_chunks} chunks of {chunk_size}")
        
        for chunk_idx in range(0, len(repos), chunk_size):
            chunk = repos[chunk_idx:chunk_idx + chunk_size]
            chunk_num = (chunk_idx // chunk_size) + 1
            
            self.logger.info(f"Processing chunk {chunk_num}/{total_chunks} ({len(chunk)} repositories)")
            
            # Process chunk with limited threading for org creation (to avoid rate limits)
            org_threads = min(3, len(chunk))  # Use fewer threads for org creation
            
            with ThreadPoolExecutor(max_workers=org_threads) as executor:
                future_to_repo = {
                    executor.submit(self._create_org_for_repo, repo): repo 
                    for repo in chunk
                }
                
                # Process completed org creation tasks
                for future in as_completed(future_to_repo):
                    try:
                        repo = future_to_repo[future]
                        success = future.result()
                        
                        if not success:
                            repo.import_status = "failed"
                            repo.error_message = "Failed to create organization"
                            with self.stats_lock:
                                self.stats['failed_imports'] += 1
                                
                    except Exception as e:
                        repo = future_to_repo[future]
                        self.logger.error(f"Exception creating org for {repo.owner}/{repo.repo}: {e}")
                        repo.import_status = "failed"
                        repo.error_message = str(e)
                        with self.stats_lock:
                            self.stats['failed_imports'] += 1
            
            # Progress update after each chunk
            processed_so_far = min(chunk_idx + chunk_size, len(repos))
            progress = (processed_so_far / len(repos)) * 100
            self.logger.info(f"Organization creation progress: {processed_so_far}/{len(repos)} ({progress:.1f}%)")
        
        return repos
    
    def _create_org_for_repo(self, repo: RepoInfo) -> bool:
        """Helper method to create organization for a single repository."""
        try:
            org_id = self.create_organization(repo)
            if org_id:
                repo.org_id = org_id
                repo.org_created = True
                return True
            else:
                return False
        except Exception as e:
            self.logger.error(f"Exception creating org for {repo.owner}/{repo.repo}: {e}")
            return False

    def batch_import_repositories(self, repos: List[RepoInfo]) -> List[RepoInfo]:
        """Batch import repositories into their organizations with chunked processing."""
        self.logger.info("Phase 2: Importing repositories...")
        
        # Filter to only repos with valid org_id
        valid_repos = [repo for repo in repos if repo.org_id and repo.import_status != "failed"]
        
        if not valid_repos:
            self.logger.warning("No valid repositories to import")
            return repos
        
        # Process imports in chunks for better memory management and progress tracking
        chunk_size = min(self.import_chunk_size, len(valid_repos))
        total_chunks = (len(valid_repos) + chunk_size - 1) // chunk_size
        
        self.logger.info(f"Importing {len(valid_repos)} repositories in {total_chunks} chunks of {chunk_size}")
        
        for chunk_idx in range(0, len(valid_repos), chunk_size):
            chunk = valid_repos[chunk_idx:chunk_idx + chunk_size]
            chunk_num = (chunk_idx // chunk_size) + 1
            
            self.logger.info(f"Importing chunk {chunk_num}/{total_chunks} ({len(chunk)} repositories)")
            
            # Use full threading for imports (they're less rate-limited)
            import_threads = min(self.max_threads, len(chunk))
            
            with ThreadPoolExecutor(max_workers=import_threads) as executor:
                # Submit all import tasks for this chunk
                future_to_repo = {
                    executor.submit(self.import_repository, repo, repo.org_id): repo 
                    for repo in chunk
                }
                
                # Process completed tasks
                for future in as_completed(future_to_repo):
                    try:
                        repo = future_to_repo[future]
                        success = future.result()
                        
                        # Note: success/failure counts are already handled in import_repository method
                        # No need to double-count here
                        
                        # Log progress
                        with self.stats_lock:
                            self.stats['processed'] += 1
                            progress = (self.stats['processed'] / self.stats['total_repos']) * 100
                            self.logger.info(f"Import progress: {self.stats['processed']}/{self.stats['total_repos']} ({progress:.1f}%)")
                            
                    except Exception as e:
                        repo = future_to_repo[future]
                        self.logger.error(f"Exception importing {repo.owner}/{repo.repo}: {e}")
                        repo.import_status = "failed"
                        repo.error_message = str(e)
                        with self.stats_lock:
                            self.stats['failed_imports'] += 1
                            self.stats['processed'] += 1
            
            # Chunk completion summary
            chunk_processed = min(chunk_idx + chunk_size, len(valid_repos))
            self.logger.info(f"Completed chunk {chunk_num}/{total_chunks} - {chunk_processed}/{len(valid_repos)} repositories processed")
        
        return repos

    def process_repositories(self, repos: List[RepoInfo]) -> List[RepoInfo]:
        """Process all repositories using batch mode (default workflow)."""
        self.logger.info(f"Starting batch processing for {len(repos)} repositories...")
        
        # Phase 1: Create organizations
        self.logger.info("Phase 1: Creating organizations...")
        repos = self.batch_create_organizations(repos)
        
        # Phase 2: Import repositories
        self.logger.info("Phase 2: Importing repositories...")
        results = self.batch_import_repositories(repos)
        
        return results

    def save_results(self, results: List[RepoInfo], output_file: str = None):
        """Save results to CSV file."""
        if not output_file:
            mode = "create_orgs" if self.create_orgs else "existing_org"
            output_file = f"import_results_{mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([
                    'Repository URL', 'Owner', 'Repository', 'Import Status', 'Error Message'
                ])
                
                for repo in results:
                    writer.writerow([
                        repo.url, repo.owner, repo.repo, repo.import_status, repo.error_message or ''
                    ])
            
            self.logger.info(f"Results saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

    def print_summary(self):
        """Print processing summary."""
        print("\n" + "="*60)
        print("IMPORT SUMMARY")
        print("="*60)
        print(f"Mode: Create Organizations and Import")
        print(f"Total repositories: {self.stats['total_repos']}")
        print(f"Processed: {self.stats['processed']}")
        print(f"Successful imports: {self.stats['successful_imports']}")
        print(f"Failed imports: {self.stats['failed_imports']}")
        print(f"Organizations created: {self.stats['orgs_created']}")
        print(f"Organizations found existing: {self.stats['orgs_existing']}")
        
        if self.stats['total_repos'] > 0:
            success_rate = (self.stats['successful_imports'] / self.stats['total_repos']) * 100
            print(f"Success rate: {success_rate:.1f}%")
        
        print("="*60)


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\nReceived interrupt signal. Shutting down gracefully...")
    sys.exit(0)


def main():
    """Main function."""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Import GitHub repositories into Snyk",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create organizations and import repositories
  python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv
  
  # Use repo-only naming (orgs named after repo, not owner-repo)
  python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --org-naming repo-only
  
  # Import with specific integration type and source org
  python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --integration-type github-enterprise --source-org-id SOURCE_ORG_ID
  
  # Using environment variable for source org
  SNYK_SOURCE_ORG_ID=SOURCE_ORG_ID python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --integration-type github-enterprise
  
  # Advanced usage
  python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --threads 10 --rate-limit 5
        """
    )
    
    parser.add_argument('--snyk-token', required=True, help='Snyk API token')
    parser.add_argument('--group-id', required=True, help='Snyk group ID (required for creating organizations)')
    parser.add_argument('--source-org-id', help='Source organization ID (can also use SNYK_SOURCE_ORG_ID env var)')
    parser.add_argument('--csv-file', required=True, help='CSV file containing GitHub repository URLs')
    parser.add_argument('--integration-type', default='github',
                       choices=['github', 'github-enterprise', 'gitlab', 'bitbucket-cloud', 'bitbucket-server', 'azure-repos'],
                       help='Integration type for repository import (default: github)')
    parser.add_argument('--region', default='SNYK-US-01', 
                       choices=['SNYK-US-01', 'SNYK-US-02', 'SNYK-EU-01', 'SNYK-AU-01'],
                       help='Snyk region (default: SNYK-US-01)')
    parser.add_argument('--threads', type=int, default=10, 
                       help='Number of threads for parallel processing (default: 10)')
    parser.add_argument('--rate-limit', type=float, default=20.0,
                       help='Snyk API calls per second (default: 20.0, max: 27.0)')
    parser.add_argument('--org-naming', default='owner-repo',
                       choices=['owner-repo', 'repo-only'],
                       help='Organization naming convention (default: owner-repo)')
    parser.add_argument('--org-chunk-size', type=int, default=20,
                       help='Number of repositories to process per chunk during organization creation (default: 20)')
    parser.add_argument('--import-chunk-size', type=int, default=20,
                       help='Number of repositories to process per chunk during import (default: 20)')
    parser.add_argument('--output', help='Output CSV file for results (optional)')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.csv_file):
        print(f"Error: CSV file '{args.csv_file}' not found")
        sys.exit(1)
    
    if args.threads < 1 or args.threads > 50:
        print("Error: Thread count must be between 1 and 50")
        sys.exit(1)
    
    if args.rate_limit <= 0 or args.rate_limit > 100:
        print("Error: Rate limit must be between 0 and 100 calls per second")
        sys.exit(1)
    
    # Get source org ID from command line or environment variable
    source_org_id = args.source_org_id or os.getenv('SNYK_SOURCE_ORG_ID')
    
    try:
        # Initialize importer
        importer = SnykRepoImporter(
            token=args.snyk_token,
            group_id=args.group_id,
            region=args.region,
            rate_limit=args.rate_limit,
            max_threads=args.threads,
            create_orgs=True,  # Always create organizations
            integration_type=args.integration_type,
            source_org_id=source_org_id,
            org_naming=args.org_naming,
            org_chunk_size=args.org_chunk_size,
            import_chunk_size=args.import_chunk_size
        )
        
        # Read CSV file
        repos = importer.read_csv_file(args.csv_file)
        
        if not repos:
            print("No valid repositories found in CSV file")
            sys.exit(1)
        
        # Process repositories using batch mode (default workflow)
        print(f"Starting batch processing for {len(repos)} repositories...")
        results = importer.process_repositories(repos)
        
        # Save results
        importer.save_results(results, args.output)
        
        # Print summary
        importer.print_summary()
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()