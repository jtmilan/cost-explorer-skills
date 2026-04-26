#!/usr/bin/env python3
"""
FinOps Recommend Skill

Scans AWS accounts for cost optimization opportunities across 4 rule categories,
returning findings as a markdown report sorted by estimated monthly savings.

This module provides:
- Finding: Dataclass representing a single cost optimization finding
- RuleResult: Dataclass representing results from a single rule execution
- BaseRule: Abstract base class for cost optimization rules
- UntaggedSpendRule: Rule to detect resources missing required cost-allocation tags
- FixtureProvider: Static class providing deterministic fixture data for --dry-run mode
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional


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


class UntaggedSpendRule(BaseRule):
    """Detects resources missing required cost-allocation tags.

    AWS APIs:
        - CostExplorer.GetCostAndUsage:
            GroupBy=[{Type: TAG, Key: <required_tag>}]
            TimePeriod=last 30 days

    Detection Logic:
        1. Query Cost Explorer grouped by each required tag
        2. Find resources where tag value is empty or missing
        3. Aggregate untagged spend by resource

    Required Tags (hardcoded):
        - "Environment"
        - "CostCenter"

    Savings Estimation:
        Returns $0.00 (tagging doesn't directly save money,
        but enables cost attribution)

    Fix Command:
        aws ec2 create-tags --resources {resource_id} --tags Key=Environment,Value=TBD Key=CostCenter,Value=TBD
    """

    REQUIRED_TAGS: List[str] = ["Environment", "CostCenter"]
    LOOKBACK_DAYS: int = 30

    def __init__(self):
        """Initialize UntaggedSpendRule with AWS Cost Explorer client."""
        self._ce_client = None

    def _get_ce_client(self):
        """Lazy initialization of Cost Explorer client."""
        if self._ce_client is None:
            import boto3
            self._ce_client = boto3.client('ce', region_name='us-east-1')
        return self._ce_client

    @property
    def rule_id(self) -> str:
        return "untagged-spend"

    def execute(self) -> RuleResult:
        """Execute untagged spend detection.

        Returns:
            RuleResult with findings for resources missing required tags,
            or error message if AWS calls fail.
        """
        try:
            findings = self._detect_untagged_resources()
            return RuleResult(rule_id=self.rule_id, findings=findings, error=None)
        except Exception as e:
            # Import botocore here to handle specific exceptions
            import botocore.exceptions
            if isinstance(e, botocore.exceptions.NoCredentialsError):
                return RuleResult(
                    rule_id=self.rule_id,
                    findings=[],
                    error=f"AWS credentials not found: {e}"
                )
            elif isinstance(e, botocore.exceptions.ClientError):
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                return RuleResult(
                    rule_id=self.rule_id,
                    findings=[],
                    error=f"{error_code}: {e}"
                )
            else:
                return RuleResult(
                    rule_id=self.rule_id,
                    findings=[],
                    error=f"Unexpected error: {e}"
                )

    def _detect_untagged_resources(self) -> List[Finding]:
        """Detect resources missing required tags using Cost Explorer.

        Returns:
            List of Finding objects for resources with missing or empty tags.
        """
        ce_client = self._get_ce_client()
        findings = []

        # Calculate time period (last 30 days)
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=self.LOOKBACK_DAYS)

        # Track resources with missing tags
        untagged_resources = set()

        # Query Cost Explorer for each required tag
        for tag in self.REQUIRED_TAGS:
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'TAG',
                        'Key': tag
                    }
                ]
            )

            # Parse response and find resources with missing or empty tag values
            for result in response.get('ResultsByTime', []):
                for group in result.get('Groups', []):
                    # Group key format is "tag_key$tag_value"
                    keys = group.get('Keys', [])
                    if keys:
                        key_value = keys[0]
                        # Extract tag value from the key
                        # Format: "Environment$" (empty) or "Environment$production"
                        tag_value = key_value.split('$', 1)[1] if '$' in key_value else ''

                        # Check for empty or missing tag values
                        if not tag_value or tag_value == '':
                            # Get the amount for this untagged spend
                            amount = float(group.get('Metrics', {}).get('UnblendedCost', {}).get('Amount', '0'))
                            if amount > 0:
                                # We can't get specific resource IDs from Cost Explorer grouping
                                # So we use a placeholder to indicate untagged resources
                                untagged_resources.add(f"untagged-{tag}")

        # Create findings for each resource with missing tags
        for resource_id in untagged_resources:
            # Determine which tags are missing based on the resource_id pattern
            missing_tags = [tag for tag in self.REQUIRED_TAGS if f"untagged-{tag}" in untagged_resources]

            if missing_tags:
                # Create ARN using a placeholder pattern since Cost Explorer
                # doesn't provide specific resource ARNs for grouped data
                arn = f"arn:aws:ce:us-east-1:untagged:cost/{resource_id}"

                finding = Finding(
                    arn=arn,
                    finding=f"Resources missing required tags: {', '.join(missing_tags)}",
                    est_monthly_saved_usd=0.00,
                    fix_command=f"aws ec2 create-tags --resources {resource_id} --tags Key=Environment,Value=TBD Key=CostCenter,Value=TBD"
                )
                findings.append(finding)
                break  # Only add one finding per untagged group

        return findings


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
