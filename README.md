# Cost Explorer Query Skill

## Overview

Cost Explorer Query is a Claude Code skill that wraps AWS Cost Explorer's `get-cost-and-usage` API with a developer-friendly CLI interface. It enables engineers to query AWS cost and usage data without writing boto3 boilerplate. The skill accepts start/end dates and grouping dimensions as CLI arguments, calls AWS Cost Explorer, and returns a formatted markdown table sorted by cost with a grand total row. It supports `--dry-run` mode for offline testing with fixture data and provides clear error messages for missing credentials or API permission denial.

## Prerequisites

- Python 3.9 or higher
- AWS credentials configured via AWS CLI or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
- boto3 library (installed via `install.sh`)

## Installation

Run the installation script to set up dependencies:

```bash
./install.sh
```

This script symlinks the skill into `~/.claude/skills/` and installs required Python packages (boto3, pytest).

## Usage

### Help

```
usage: query.py [-h] [--start START] [--end END] [--group-by GROUP_BY]
                [--dry-run]

Query AWS Cost Explorer for cost and usage data

options:
  -h, --help           show this help message and exit
  --start START        Start date in YYYY-MM-DD format
  --end END            End date in YYYY-MM-DD format
  --group-by GROUP_BY  Grouping dimension: service, account, linked-account,
                       or tag:<name>
  --dry-run            Use fixture data instead of querying AWS (for testing)
```

### Arguments

- `--start YYYY-MM-DD` (required unless `--dry-run`) — Start date for cost query
- `--end YYYY-MM-DD` (required unless `--dry-run`) — End date for cost query
- `--group-by {service|account|linked-account|tag:<name>}` (required unless `--dry-run`) — Group results by dimension:
  - `service` — AWS service (e.g., EC2, RDS, Lambda, S3)
  - `account` — Payer account (AWS account number)
  - `linked-account` — Linked account in consolidated billing
  - `tag:<tagname>` — Custom tag key (e.g., `tag:Environment`)
- `--dry-run` (optional) — Use fixture data instead of querying AWS (for testing without credentials)

## Examples

### Example 1: Query costs grouped by service

Query the last 30 days of costs grouped by AWS service in `--dry-run` mode:

```bash
python skills/cost-explorer-query/query.py --dry-run --group-by service
```

Expected output:

```
| Service | Cost USD |
|---------|----------|
| EC2 | $1,234.56 |
| RDS | $567.89 |
| Lambda | $123.45 |
| S3 | $89.10 |
| TOTAL | $2,015.00 |
```

### Example 2: Query costs grouped by account

Query costs grouped by AWS account number in `--dry-run` mode:

```bash
python skills/cost-explorer-query/query.py --dry-run --group-by account
```

Expected output:

```
| Account | Cost USD |
|---------|----------|
| 123456789012 | $1,500.00 |
| 210987654321 | $800.00 |
| 345678901234 | $715.00 |
| TOTAL | $3,015.00 |
```

### Example 3: Query costs for Q1 2024 grouped by linked-account

Query Q1 2024 (January through March) costs grouped by linked account:

```bash
python skills/cost-explorer-query/query.py --dry-run --start 2024-01-01 --end 2024-03-31 --group-by linked-account
```

Expected output:

```
| Linked Account | Cost USD |
|----------------|----------|
| 123456789012 | $1,500.00 |
| 210987654321 | $800.00 |
| 345678901234 | $715.00 |
| TOTAL | $3,015.00 |
```

## Testing

Run the test suite to verify the skill works correctly:

```bash
pytest tests/test_query.py -v
```

All tests use mocked AWS responses (via `botocore.stub.Stubber`) and do not require live AWS credentials or network access. Tests verify:
- Happy path: Successful cost queries with proper formatting and sorting
- Error handling: Missing credentials and permission denial scenarios
- Fixture data: Deterministic output in `--dry-run` mode

## Error Handling

The skill provides clear error messages for common issues:

- **Missing AWS Credentials**: If AWS credentials are not configured, the skill outputs:
  ```
  Error: AWS credentials not found. Configure credentials via AWS CLI or environment variables.
  ```
  Exit code: 1

- **Permission Denied**: If the AWS account lacks `ce:GetCostAndUsage` permission, the skill outputs:
  ```
  Error: AWS Cost Explorer API access denied. Ensure IAM permissions include ce:GetCostAndUsage.
  ```
  Exit code: 1

- **Invalid Arguments**: If CLI arguments are malformed (e.g., invalid date format), argparse prints usage and exits with code 2.

## cost-anomaly-investigate Skill

The cost-anomaly-investigate skill investigates the root causes of AWS cost spikes. Given a date and service, it queries Phase 1's cost data to confirm elevated costs, then gathers CloudWatch metrics and CloudTrail events to identify likely causes.

### Usage

```bash
python skills/cost-anomaly-investigate/investigate.py --date YYYY-MM-DD --service <service> [--dry-run]
```

**Arguments:**
- `--date YYYY-MM-DD` (required): Date to investigate in YYYY-MM-DD format (e.g., 2024-03-15)
- `--service <service>` (required): AWS service name (e.g., EC2, RDS, Lambda, S3, DynamoDB, etc.)
- `--dry-run` (optional): Use fixture data instead of querying AWS (for testing without credentials)

### Example: Investigate EC2 Cost Spike (Dry-Run)

```bash
python skills/cost-anomaly-investigate/investigate.py --date 2024-03-15 --service EC2 --dry-run
```

**Expected Output:**

```markdown
# Cost Spike: $5,234.56 on 2024-03-15 (EC2)

## Spike Summary
Baseline (previous month average): $1,200.00/day
Spike cost (2024-03-15): $6,434.56/day
Delta: $5,234.56 (435.3% increase)

## Likely Causes
1. EC2 instance launch surge: 15 instances launched on 2024-03-15
2. Data transfer spike: NetworkOut exceeded 100 Mbps
3. Configuration or deployment activity: 25 mutating events detected

## Evidence

### CloudTrail Events
| Timestamp | Principal | Action | Resources |
|-----------|-----------|--------|-----------|
| 2024-03-15T10:30:45Z | arn:aws:iam::123456789012:user/alice | RunInstances | i-1234567890abcdef0 |
| 2024-03-15T10:45:20Z | arn:aws:iam::123456789012:role/lambda-role | RunInstances | i-0987654321fedcba0 |

### Metrics
CPUUtilization: 45.2% average, max 89.5%
NetworkIn: 1.2 GB total
NetworkOut: 2.5 GB total

---
Investigation completed at 2024-03-15T14:30:00Z
```

### Error Handling

- **Invalid date format**: Exit code 2; error message about date format
- **Unknown service**: Exit code 2; error message with list of valid services
- **Missing credentials**: Exit code 1; error message about AWS credentials
- **AWS API error**: Exit code 1; error message about API failure

## finops-recommend Skill

The finops-recommend skill scans AWS accounts for cost optimization opportunities across 4 rule categories:
- **idle-ec2**: EC2 instances with <5% avg CPU over 7 days
- **oversized-rds**: RDS instances using <30% provisioned capacity
- **orphan-ebs**: Unattached EBS volumes older than 14 days
- **untagged-spend**: Resources missing required cost-allocation tags

### Usage

```bash
python skills/finops-recommend/recommend.py [--dry-run] [--rules RULES]
```

**Arguments:**
- `--dry-run` (optional): Use fixture data instead of querying AWS
- `--rules RULES` (optional): Comma-separated rule subset. Valid: idle-ec2,oversized-rds,orphan-ebs,untagged-spend

### Example: Dry-Run Mode

```bash
python skills/finops-recommend/recommend.py --dry-run
```

**Expected Output:**

```markdown
# FinOps Recommendations Report

Generated: 2024-03-15T14:30:00Z
Rules executed: idle-ec2, oversized-rds, orphan-ebs, untagged-spend

## Findings (sorted by estimated savings)

| ARN | Finding | Est. Monthly Savings | Fix Command |
|-----|---------|---------------------|-------------|
| arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456 | EC2 instance i-0abc123def456 has 2.3% avg CPU over 7d | $156.00 | `aws ec2 stop-instances --instance-ids i-0abc123def456` |
| arn:aws:rds:us-east-1:123456789012:db:mydb | RDS instance mydb using 12% of provisioned capacity over 7d | $89.50 | `aws rds modify-db-instance --db-instance-identifier mydb --db-instance-class db.t3.medium` |
| arn:aws:ec2:us-east-1:123456789012:volume/vol-0xyz789 | EBS volume vol-0xyz789 unattached for 21 days | $45.60 | `aws ec2 delete-volume --volume-id vol-0xyz789` |
| arn:aws:ec2:us-east-1:123456789012:instance/i-untagged | Resources missing required tags: Environment, CostCenter | $0.00 | `aws ec2 create-tags --resources i-untagged --tags Key=Environment,Value=TBD Key=CostCenter,Value=TBD` |

Total estimated monthly savings: $291.10
```

### Error Handling

- **Rule failures are isolated**: If one rule fails (e.g., missing permissions), other rules continue executing
- **Rule errors reported in output**: Failed rules appear in a "Rule Errors" section
- **Exit code 0**: At least one rule succeeded
- **Exit code 1**: All rules failed

## Project Structure

```
.
├── README.md                          # This file
├── LICENSE                            # Apache License 2.0
├── pyproject.toml                     # Project metadata and dependencies
├── install.sh                         # Installation script
├── skills/
│   ├── cost-explorer-query/
│   │   ├── SKILL.md                   # Skill metadata
│   │   └── query.py                   # Main CLI implementation
│   ├── cost-anomaly-investigate/
│   │   ├── SKILL.md                   # Skill metadata
│   │   └── investigate.py             # Main CLI implementation
│   └── finops-recommend/
│       ├── SKILL.md                   # Skill metadata
│       └── recommend.py               # Main CLI implementation
└── tests/
    ├── test_query.py                  # Pytest test suite for query
    ├── test_investigate.py            # Pytest test suite for investigate
    └── test_recommend.py              # Pytest test suite for recommend
```

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.

## Notes

- **Costs**: All costs are in USD (UnblendedCost metric) with 2 decimal places and thousands separators.
- **Sorting**: Results are sorted descending by cost (highest cost first).
- **Pagination**: The skill automatically handles AWS Cost Explorer pagination; large result sets are aggregated transparently.
- **Date Format**: Dates must be in strict `YYYY-MM-DD` format (e.g., `2024-01-15`). No fuzzy parsing is supported.
- **Fixture Data**: The `--dry-run` mode returns representative sample data for testing without AWS access. This data is static and deterministic.
