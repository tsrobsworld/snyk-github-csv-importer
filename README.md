# Snyk Repository Importer

Bulk import GitHub repositories into Snyk organizations from a CSV file.

## Features

- Creates Snyk organizations and imports repositories in batches
- Skips existing organizations automatically
- Supports GitHub, GitLab, Bitbucket, and Azure Repos
- Configurable rate limiting and multi-threading
- CSV output with detailed results

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage
python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv

# Repo-only naming
python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --org-naming repo-only

# GitHub Enterprise
python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --integration-type github-enterprise --source-org-id SOURCE_ORG_ID

# High performance
python3 snyk_repo_importer.py --snyk-token YOUR_TOKEN --group-id GROUP_ID --csv-file repos.csv --threads 15 --rate-limit 20
```

## CSV Format

```csv
https://github.com/owner/repo1.git
https://github.com/owner/repo2.git
https://github.com/owner/repo3.git
```

## Options

| Option | Required | Description | Default |
|--------|----------|-------------|---------|
| `--snyk-token` | Yes | Snyk API token | - |
| `--group-id` | Yes | Snyk group ID | - |
| `--csv-file` | Yes | CSV file with repository URLs | - |
| `--org-naming` | No | Naming: `owner-repo` or `repo-only` | `owner-repo` |
| `--integration-type` | No | `github`, `github-cloud-app`, `github-enterprise`, etc. | `github` |
| `--threads` | No | Number of threads | `10` |
| `--rate-limit` | No | API calls per second | `20.0` |

## Output

Generates a CSV file with import results including status and error messages.

## Requirements

- Python 3.7+
- Snyk API token with organization creation permissions
- Snyk group ID

## Environment Variables

For enterprise environments with HTTP proxies:

```bash
# HTTP proxy for GitHub API calls
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"

# Optional: bypass proxy for specific hosts
export NO_PROXY="localhost,127.0.0.1,api.snyk.io"
```

## License

Apache License 2.0