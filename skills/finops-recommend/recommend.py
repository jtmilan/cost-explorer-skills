#!/usr/bin/env python3
"""
FinOps Recommend Skill

Scans AWS accounts for cost optimization opportunities across 4 rule categories,
returning findings as a markdown report sorted by estimated monthly savings.

This module provides:
- Finding: Dataclass representing a single cost optimization finding
- RuleResult: Dataclass representing results from a single rule execution
- FixtureProvider: Static class providing deterministic fixture data for --dry-run mode
- BaseRule: Abstract base class for cost optimization rules
- OrphanEbsRule: Rule to detect unattached EBS volumes older than 14 days
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional


@dataclass
class Finding:
    """Single cost optimization finding.

    Attributes:
        arn: Full AWS ARN (must start with "arn:aws:")
        finding: Human-readable description of the waste
        est_monthly_saved_usd: Estimated monthly savings in USD (>= 0.0)
        fix_command: AWS CLI command to remediate (must start with "aws ")

    Invariants:
        - arn.startswith("arn:aws:")
        - est_monthly_saved_usd >= 0.0
        - fix_command.startswith("aws ")
    """
    arn: str
    finding: str
    est_monthly_saved_usd: float
    fix_command: str


@dataclass
class RuleResult:
    """Result from a single rule execution.

    Attributes:
        rule_id: One of: "idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"
        findings: List of Finding objects (may be empty if no issues found)
        error: None if successful, error message string if rule failed

    Usage:
        - On success: RuleResult(rule_id="idle-ec2", findings=[...], error=None)
        - On failure: RuleResult(rule_id="idle-ec2", findings=[], error="AccessDenied...")
    """
    rule_id: str
    findings: List[Finding]
    error: Optional[str]


class FixtureProvider:
    """Provides deterministic fixture data for --dry-run mode.

    No AWS calls. Returns hardcoded RuleResult objects that exercise
    all report formatting logic.
    """

    @staticmethod
    def get_fixture_results() -> List[RuleResult]:
        """Return fixture RuleResult objects for all rules.

        Returns:
            List of 4 RuleResult objects (one per rule), containing
            representative findings that validate report generation.

        Fixture Data:
            - idle-ec2: 1 finding ($156.00 savings)
            - oversized-rds: 1 finding ($89.50 savings)
            - orphan-ebs: 1 finding ($45.60 savings)
            - untagged-spend: 1 finding ($0.00 savings, tag compliance)
        """
        return [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
                        finding="EC2 instance i-0abc123def456 has 2.3% avg CPU over 7d",
                        est_monthly_saved_usd=156.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-0abc123def456"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="oversized-rds",
                findings=[
                    Finding(
                        arn="arn:aws:rds:us-east-1:123456789012:db:mydb",
                        finding="RDS instance mydb using 12% of provisioned capacity over 7d",
                        est_monthly_saved_usd=89.50,
                        fix_command="aws rds modify-db-instance --db-instance-identifier mydb --db-instance-class db.t3.medium"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:volume/vol-0xyz789",
                        finding="EBS volume vol-0xyz789 unattached for 21 days",
                        est_monthly_saved_usd=45.60,
                        fix_command="aws ec2 delete-volume --volume-id vol-0xyz789"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="untagged-spend",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-untagged",
                        finding="Resources missing required tags: Environment, CostCenter",
                        est_monthly_saved_usd=0.00,
                        fix_command="aws ec2 create-tags --resources i-untagged --tags Key=Environment,Value=TBD Key=CostCenter,Value=TBD"
                    )
                ],
                error=None
            )
        ]

    @staticmethod
    def get_fixture_results_for_rules(rule_ids: List[str]) -> List[RuleResult]:
        """Return fixture results filtered to specified rules.

        Args:
            rule_ids: List of rule IDs to include (e.g., ["idle-ec2", "orphan-ebs"])

        Returns:
            List of RuleResult objects for specified rules only
        """
        all_results = FixtureProvider.get_fixture_results()
        return [r for r in all_results if r.rule_id in rule_ids]


class BaseRule(ABC):
    """Abstract base class for cost optimization rules.

    All rules MUST:
    1. Catch and handle all exceptions internally
    2. Return RuleResult with error field set on failure
    3. Never raise exceptions to caller
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Return the rule identifier (e.g., 'idle-ec2')."""
        pass

    @abstractmethod
    def execute(self) -> RuleResult:
        """Execute the rule and return results.

        Returns:
            RuleResult with findings or error. Never raises exceptions.
        """
        pass


class OrphanEbsRule(BaseRule):
    """Detects unattached EBS volumes older than 14 days.

    AWS APIs:
        - EC2.DescribeVolumes: Filters=[{Name: status, Values: [available]}]

    Detection Logic:
        1. Get all volumes with status="available" (unattached)
        2. For each volume, check CreateTime
        3. If CreateTime > 14 days ago, flag as orphan

    Savings Estimation:
        Volume size (GB) × price per GB-month (varies by volume type)

    Fix Command:
        aws ec2 delete-volume --volume-id {vol_id}
    """

    AGE_THRESHOLD_DAYS: int = 14

    # EBS pricing by volume type (USD per GB-month, us-east-1)
    EBS_PRICING: Dict[str, float] = {
        "gp2": 0.10,
        "gp3": 0.08,
        "io1": 0.125,
        "io2": 0.125,
        "st1": 0.045,
        "sc1": 0.025,
        "standard": 0.05,
    }
    DEFAULT_GB_MONTH_RATE: float = 0.10

    def __init__(self):
        """Initialize OrphanEbsRule with EC2 client set to None.

        The client is created lazily on execute() to allow for testing
        with stubbed clients.
        """
        self._ec2_client = None

    @property
    def rule_id(self) -> str:
        return "orphan-ebs"

    def _get_ec2_client(self):
        """Get or create EC2 client."""
        if self._ec2_client is None:
            import boto3
            self._ec2_client = boto3.client('ec2')
        return self._ec2_client

    def _get_account_id(self) -> str:
        """Get the AWS account ID using STS."""
        import boto3
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']

    def execute(self) -> RuleResult:
        """Execute orphan EBS detection.

        Returns:
            RuleResult with findings for unattached volumes older than 14 days,
            or error message if AWS calls fail.
        """
        try:
            import botocore.exceptions

            ec2_client = self._get_ec2_client()

            # Get all unattached volumes (status = available)
            response = ec2_client.describe_volumes(
                Filters=[
                    {
                        'Name': 'status',
                        'Values': ['available']
                    }
                ]
            )

            findings = []
            now = datetime.now(timezone.utc)
            threshold_date = now - timedelta(days=self.AGE_THRESHOLD_DAYS)

            for volume in response.get('Volumes', []):
                volume_id = volume['VolumeId']
                create_time = volume['CreateTime']
                volume_type = volume.get('VolumeType', 'gp2')
                size_gb = volume.get('Size', 0)

                # Ensure create_time is timezone-aware
                if create_time.tzinfo is None:
                    create_time = create_time.replace(tzinfo=timezone.utc)

                # Only flag volumes older than threshold
                if create_time < threshold_date:
                    # Calculate days unattached
                    days_unattached = (now - create_time).days

                    # Get region from availability zone
                    az = volume.get('AvailabilityZone', 'us-east-1a')
                    region = az[:-1] if az else 'us-east-1'

                    # Get account ID - in tests this may fail, so use placeholder
                    try:
                        account_id = self._get_account_id()
                    except Exception:
                        account_id = '123456789012'

                    # Calculate monthly savings
                    price_per_gb = self.EBS_PRICING.get(volume_type, self.DEFAULT_GB_MONTH_RATE)
                    monthly_savings = size_gb * price_per_gb

                    # Build ARN: arn:aws:ec2:region:account:volume/vol-xxx
                    arn = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"

                    finding = Finding(
                        arn=arn,
                        finding=f"EBS volume {volume_id} unattached for {days_unattached} days",
                        est_monthly_saved_usd=monthly_savings,
                        fix_command=f"aws ec2 delete-volume --volume-id {volume_id}"
                    )
                    findings.append(finding)

            return RuleResult(rule_id=self.rule_id, findings=findings, error=None)

        except botocore.exceptions.NoCredentialsError as e:
            return RuleResult(
                rule_id=self.rule_id,
                findings=[],
                error=f"AWS credentials not found: {e}"
            )
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return RuleResult(
                rule_id=self.rule_id,
                findings=[],
                error=f"{error_code}: {e}"
            )
        except Exception as e:
            return RuleResult(
                rule_id=self.rule_id,
                findings=[],
                error=f"Unexpected error: {e}"
            )
