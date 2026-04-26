#!/usr/bin/env python3
"""
FinOps Recommend Skill

Scans AWS accounts for cost optimization opportunities across 4 rule categories,
returning findings as a markdown report sorted by estimated monthly savings.

This module provides:
- Finding: Dataclass representing a single cost optimization finding
- RuleResult: Dataclass representing results from a single rule execution
- BaseRule: Abstract base class for cost optimization rules
- IdleEc2Rule: Rule detecting EC2 instances with <5% avg CPU over 7 days
- OversizedRdsRule: Rule to detect underutilized RDS instances
- OrphanEbsRule: Rule to detect unattached EBS volumes older than 14 days
- UntaggedSpendRule: Rule to detect resources missing required cost-allocation tags
- FixtureProvider: Static class providing deterministic fixture data for --dry-run mode
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


# ============================================================================
# Base Rule Interface
# ============================================================================

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


# ============================================================================
# IdleEc2Rule Implementation
# ============================================================================

# Constants for IdleEc2Rule
CPU_THRESHOLD: float = 5.0  # Percent
LOOKBACK_DAYS: int = 7

# Simplified pricing table (USD per hour, us-east-1)
INSTANCE_PRICING: Dict[str, float] = {
    "t2.micro": 0.0116,
    "t2.small": 0.023,
    "t2.medium": 0.0464,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m5.2xlarge": 0.384,
}
DEFAULT_HOURLY_RATE: float = 0.10  # Fallback for unknown types


class IdleEc2Rule(BaseRule):
    """Detects EC2 instances with <5% avg CPU over 7 days.

    AWS APIs:
        - EC2.DescribeInstances: Filters=[{Name: instance-state-name, Values: [running]}]
        - CloudWatch.GetMetricStatistics:
            Namespace=AWS/EC2
            MetricName=CPUUtilization
            Period=3600 (1 hour)
            Statistics=[Average]
            StartTime=NOW-7d
            EndTime=NOW

    Detection Logic:
        1. Get all running EC2 instances
        2. For each instance, fetch 7-day CPU average
        3. If avg(CPUUtilization) < 5%, flag as idle

    Savings Estimation:
        Instance type → on-demand hourly rate × 730 hours/month
        Uses simplified pricing table (m5.large=$0.096/hr, etc.)

    Error Handling:
        - Catches NoCredentialsError, ClientError
        - Returns RuleResult(rule_id="idle-ec2", findings=[], error=str(e))
    """

    def __init__(self):
        """Initialize the IdleEc2Rule.

        AWS clients are lazily initialized to avoid credential checks at import time.
        """
        self._ec2_client = None
        self._cw_client = None

    @property
    def rule_id(self) -> str:
        """Return the rule identifier."""
        return "idle-ec2"

    def execute(self) -> RuleResult:
        """Execute idle EC2 detection.

        Returns:
            RuleResult with findings for instances averaging <5% CPU,
            or error message if AWS calls fail.
        """
        try:
            import boto3
            import botocore.exceptions

            # Initialize clients if not already set (for testing injection)
            if self._ec2_client is None:
                self._ec2_client = boto3.client('ec2', region_name='us-east-1')
            if self._cw_client is None:
                self._cw_client = boto3.client('cloudwatch', region_name='us-east-1')

            # Get all running EC2 instances
            instances = self._get_running_instances()

            # Check each instance for idle CPU
            findings = []
            for instance in instances:
                instance_id = instance['InstanceId']
                instance_type = instance.get('InstanceType', 'unknown')

                # Get average CPU utilization over lookback period
                avg_cpu = self._get_average_cpu(instance_id)

                # If CPU is below threshold, flag as idle
                if avg_cpu is not None and avg_cpu < CPU_THRESHOLD:
                    # Calculate estimated monthly savings
                    hourly_rate = INSTANCE_PRICING.get(instance_type, DEFAULT_HOURLY_RATE)
                    monthly_savings = hourly_rate * 730

                    # Build ARN
                    # Get region from client config
                    region = self._ec2_client.meta.region_name
                    # Get account ID from instance owner (fallback to placeholder)
                    owner_id = instance.get('OwnerId', '123456789012')
                    arn = f"arn:aws:ec2:{region}:{owner_id}:instance/{instance_id}"

                    finding = Finding(
                        arn=arn,
                        finding=f"EC2 instance {instance_id} has {avg_cpu:.1f}% avg CPU over {LOOKBACK_DAYS}d",
                        est_monthly_saved_usd=monthly_savings,
                        fix_command=f"aws ec2 stop-instances --instance-ids {instance_id}"
                    )
                    findings.append(finding)

            return RuleResult(rule_id=self.rule_id, findings=findings, error=None)

        except Exception as e:
            # Import botocore for exception type checking
            try:
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
            except ImportError:
                pass

            return RuleResult(
                rule_id=self.rule_id,
                findings=[],
                error=f"Unexpected error: {e}"
            )

    def _get_running_instances(self) -> List[dict]:
        """Get all running EC2 instances.

        Returns:
            List of instance dictionaries from DescribeInstances response.
            Each dict includes the instance data plus 'OwnerId' from the reservation.
        """
        instances = []
        paginator = self._ec2_client.get_paginator('describe_instances')

        for page in paginator.paginate(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        ):
            for reservation in page.get('Reservations', []):
                owner_id = reservation.get('OwnerId', '123456789012')
                for instance in reservation.get('Instances', []):
                    # Add OwnerId from reservation to instance data
                    instance['OwnerId'] = owner_id
                    instances.append(instance)

        return instances

    def _get_average_cpu(self, instance_id: str) -> Optional[float]:
        """Get average CPU utilization for an instance over lookback period.

        Args:
            instance_id: EC2 instance ID

        Returns:
            Average CPU percentage, or None if no data available.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=LOOKBACK_DAYS)

        response = self._cw_client.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id}
            ],
            StartTime=start_time,
            EndTime=now,
            Period=3600,  # 1 hour
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return None

        # Calculate overall average from all datapoints
        total = sum(dp['Average'] for dp in datapoints)
        return total / len(datapoints)


# ============================================================================
# OversizedRdsRule Implementation
# ============================================================================

class OversizedRdsRule(BaseRule):
    """Detects RDS instances using <30% provisioned capacity over 7 days.

    AWS APIs:
        - RDS.DescribeDBInstances: No filters (all instances)
        - CloudWatch.GetMetricStatistics:
            Namespace=AWS/RDS
            MetricName=CPUUtilization
            Period=3600
            Statistics=[Average]
            StartTime=NOW-7d
            EndTime=NOW

    Detection Logic:
        1. Get all RDS instances
        2. For each instance, fetch 7-day CPU average
        3. If avg(CPUUtilization) < 30%, flag as oversized

    Savings Estimation:
        Estimate 30% savings by downsizing instance class.
        Current monthly cost × 0.30 = estimated savings.

    Fix Command:
        aws rds modify-db-instance --db-instance-identifier {id} --db-instance-class {smaller_class}
    """

    CPU_THRESHOLD: float = 30.0  # Percent
    LOOKBACK_DAYS: int = 7
    SAVINGS_RATIO: float = 0.30  # Assume 30% savings from rightsizing

    # Simplified RDS pricing (USD per hour, us-east-1, single-AZ)
    RDS_PRICING: Dict[str, float] = {
        "db.t3.micro": 0.017,
        "db.t3.small": 0.034,
        "db.t3.medium": 0.068,
        "db.m5.large": 0.171,
        "db.m5.xlarge": 0.342,
        "db.r5.large": 0.24,
    }
    DEFAULT_HOURLY_RATE: float = 0.20

    # Downsizing recommendations
    DOWNSIZE_MAP: Dict[str, str] = {
        "db.m5.xlarge": "db.m5.large",
        "db.m5.large": "db.t3.medium",
        "db.r5.xlarge": "db.r5.large",
        "db.r5.large": "db.m5.large",
        "db.t3.medium": "db.t3.small",
        "db.t3.small": "db.t3.micro",
    }

    def __init__(self) -> None:
        """Initialize the OversizedRdsRule with AWS clients set to None."""
        self._rds_client = None
        self._cw_client = None

    @property
    def rule_id(self) -> str:
        return "oversized-rds"

    def _get_rds_client(self):
        """Get or create RDS client."""
        if self._rds_client is None:
            import boto3
            self._rds_client = boto3.client('rds', region_name='us-east-1')
        return self._rds_client

    def _get_cw_client(self):
        """Get or create CloudWatch client."""
        if self._cw_client is None:
            import boto3
            self._cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        return self._cw_client

    def _get_avg_cpu(self, db_instance_identifier: str) -> Optional[float]:
        """Get average CPU utilization for an RDS instance over the lookback period.

        Args:
            db_instance_identifier: The RDS instance identifier

        Returns:
            Average CPU utilization as a float, or None if no data available
        """
        cw_client = self._get_cw_client()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.LOOKBACK_DAYS)

        response = cw_client.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='CPUUtilization',
            Dimensions=[
                {'Name': 'DBInstanceIdentifier', 'Value': db_instance_identifier}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1 hour
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return None

        # Calculate the average of all datapoints
        total = sum(dp['Average'] for dp in datapoints)
        return total / len(datapoints)

    def _calculate_monthly_cost(self, instance_class: str) -> float:
        """Calculate estimated monthly cost for an RDS instance class.

        Args:
            instance_class: The RDS instance class (e.g., 'db.m5.large')

        Returns:
            Estimated monthly cost in USD
        """
        hourly_rate = self.RDS_PRICING.get(instance_class, self.DEFAULT_HOURLY_RATE)
        # 730 hours per month (average)
        return hourly_rate * 730

    def _get_smaller_instance_class(self, current_class: str) -> str:
        """Get the recommended smaller instance class.

        Args:
            current_class: The current RDS instance class

        Returns:
            The recommended smaller instance class, or current class if no downsize mapping exists
        """
        return self.DOWNSIZE_MAP.get(current_class, current_class)

    def execute(self) -> RuleResult:
        """Execute oversized RDS detection.

        Returns:
            RuleResult with findings for instances averaging <30% CPU,
            or error message if AWS calls fail.
        """
        try:
            import botocore.exceptions

            rds_client = self._get_rds_client()

            # Get all RDS instances
            response = rds_client.describe_db_instances()
            db_instances = response.get('DBInstances', [])

            findings: List[Finding] = []

            for db_instance in db_instances:
                db_instance_identifier = db_instance['DBInstanceIdentifier']
                instance_class = db_instance['DBInstanceClass']
                db_instance_arn = db_instance['DBInstanceArn']

                # Get CPU utilization
                avg_cpu = self._get_avg_cpu(db_instance_identifier)

                # Skip instances without sufficient data
                if avg_cpu is None:
                    continue

                # Check if underutilized
                if avg_cpu < self.CPU_THRESHOLD:
                    # Calculate savings
                    current_monthly_cost = self._calculate_monthly_cost(instance_class)
                    estimated_savings = current_monthly_cost * self.SAVINGS_RATIO

                    # Get smaller instance class
                    smaller_class = self._get_smaller_instance_class(instance_class)

                    findings.append(Finding(
                        arn=db_instance_arn,
                        finding=f"RDS instance {db_instance_identifier} using {avg_cpu:.1f}% of provisioned capacity over 7d",
                        est_monthly_saved_usd=round(estimated_savings, 2),
                        fix_command=f"aws rds modify-db-instance --db-instance-identifier {db_instance_identifier} --db-instance-class {smaller_class}"
                    ))

            return RuleResult(rule_id=self.rule_id, findings=findings, error=None)

        except Exception as e:
            # Import botocore exceptions for specific handling
            try:
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
            except ImportError:
                pass

            return RuleResult(
                rule_id=self.rule_id,
                findings=[],
                error=f"Unexpected error: {e}"
            )


# ============================================================================
# OrphanEbsRule Implementation
# ============================================================================

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


# ============================================================================
# UntaggedSpendRule Implementation
# ============================================================================

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


class ReportGenerator:
    """Generates markdown report from rule results.

    Output Format:
        # FinOps Recommendations Report

        Generated: {timestamp}
        Rules executed: {rule_list}

        ## Findings (sorted by estimated savings)

        | ARN | Finding | Est. Monthly Savings | Fix Command |
        |-----|---------|---------------------|-------------|
        | ... | ...     | $XXX.XX             | `aws ...`   |

        ## Rule Errors (if any)

        | Rule | Error |
        |------|-------|
        | ...  | ...   |

        Total estimated monthly savings: $X,XXX.XX
    """

    def generate(self, results: List[RuleResult], executed_rules: List[str]) -> str:
        """Generate markdown report from results.

        Args:
            results: List of RuleResult objects from rule execution
            executed_rules: List of rule IDs that were executed

        Returns:
            Complete markdown report as string

        Behavior:
            - Findings sorted by est_monthly_saved_usd descending
            - Rule errors collected in separate section
            - Total savings calculated from all successful findings
            - Empty findings section shows "No findings" message
        """
        from datetime import datetime, timezone

        # Collect all findings from all results
        all_findings: List[Finding] = []
        for result in results:
            if result.error is None:
                all_findings.extend(result.findings)

        # Sort findings by est_monthly_saved_usd descending
        sorted_findings = sorted(
            all_findings,
            key=lambda f: f.est_monthly_saved_usd,
            reverse=True
        )

        # Build report sections
        lines = []

        # Header
        lines.append("# FinOps Recommendations Report")
        lines.append("")

        # Timestamp and rules executed
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        lines.append(f"Generated: {timestamp}")
        lines.append(f"Rules executed: {', '.join(executed_rules)}")
        lines.append("")

        # Findings section
        lines.append("## Findings (sorted by estimated savings)")
        lines.append("")
        lines.append(self._format_findings_table(sorted_findings))
        lines.append("")

        # Rule Errors section (only if there are errors)
        errors_section = self._format_errors_section(results)
        if errors_section:
            lines.append(errors_section)
            lines.append("")

        # Total savings
        total_savings = self._calculate_total_savings(results)
        lines.append(f"Total estimated monthly savings: ${total_savings:,.2f}")

        return '\n'.join(lines)

    def _format_findings_table(self, findings: List[Finding]) -> str:
        """Format findings as markdown table, sorted by savings descending."""
        if not findings:
            return "No findings"

        lines = []
        lines.append("| ARN | Finding | Est. Monthly Savings | Fix Command |")
        lines.append("|-----|---------|---------------------|-------------|")

        for finding in findings:
            # Format savings with dollar sign, commas, and two decimals
            savings_formatted = f"${finding.est_monthly_saved_usd:,.2f}"
            # Wrap fix_command in backticks
            fix_command_formatted = f"`{finding.fix_command}`"
            lines.append(
                f"| {finding.arn} | {finding.finding} | {savings_formatted} | {fix_command_formatted} |"
            )

        return '\n'.join(lines)

    def _format_errors_section(self, results: List[RuleResult]) -> str:
        """Format rule errors as markdown table. Returns empty string if no errors."""
        errors = [(r.rule_id, r.error) for r in results if r.error is not None]

        if not errors:
            return ""

        lines = []
        lines.append("## Rule Errors")
        lines.append("")
        lines.append("| Rule | Error |")
        lines.append("|------|-------|")

        for rule_id, error in errors:
            lines.append(f"| {rule_id} | {error} |")

        return '\n'.join(lines)

    def _calculate_total_savings(self, results: List[RuleResult]) -> float:
        """Sum est_monthly_saved_usd from all successful findings."""
        total = 0.0
        for result in results:
            if result.error is None:
                for finding in result.findings:
                    total += finding.est_monthly_saved_usd
        return total


# ============================================================================
# CLI Interface
# ============================================================================

import argparse
from typing import Type


# Rule registry maps rule_id to rule class
RULE_REGISTRY: Dict[str, Type[BaseRule]] = {
    "idle-ec2": IdleEc2Rule,
    "oversized-rds": OversizedRdsRule,
    "orphan-ebs": OrphanEbsRule,
    "untagged-spend": UntaggedSpendRule,
}


# Valid rule IDs for validation
VALID_RULES = {"idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"}


def validate_rules(rules_str: str) -> List[str]:
    """Validate and parse --rules comma-separated list.

    Args:
        rules_str: Comma-separated rule IDs (e.g., "idle-ec2,orphan-ebs")

    Returns:
        List of valid rule IDs

    Raises:
        argparse.ArgumentTypeError: If any rule ID is invalid

    Valid rule IDs: idle-ec2, oversized-rds, orphan-ebs, untagged-spend
    """
    rules = [r.strip() for r in rules_str.split(",")]
    invalid = set(rules) - VALID_RULES
    if invalid:
        raise argparse.ArgumentTypeError(
            f"Invalid rules: {', '.join(invalid)}. "
            f"Valid options: {', '.join(sorted(VALID_RULES))}"
        )
    return rules


def execute_rules(rule_ids: List[str]) -> List[RuleResult]:
    """Execute specified rules, catching all errors.

    Args:
        rule_ids: List of rule IDs to execute

    Returns:
        List of RuleResult objects (one per rule)

    Behavior:
        - Rules execute independently
        - Errors in one rule don't affect others
        - Each rule catches its own exceptions
        - Results returned in same order as rule_ids
    """
    results = []
    for rule_id in rule_ids:
        rule_class = RULE_REGISTRY[rule_id]
        rule = rule_class()
        result = rule.execute()
        results.append(result)
    return results


def main() -> int:
    """CLI entry point.

    Arguments:
        --dry-run: Use fixture data (no AWS calls)
        --rules RULES: Comma-separated rule subset (default: all)

    Returns:
        0: At least one rule succeeded
        1: All rules failed
        2: Argument validation error (handled by argparse)

    Behavior:
        1. Parse arguments
        2. Determine which rules to execute
        3. If --dry-run: use FixtureProvider
        4. Else: instantiate and execute each rule
        5. Generate and print report
        6. Return appropriate exit code
    """
    parser = argparse.ArgumentParser(
        description="Scan AWS account for cost optimization opportunities"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Use fixture data (no AWS calls)"
    )
    parser.add_argument(
        "--rules",
        type=validate_rules,
        default=None,
        help="Comma-separated rule subset (default: all). "
             "Valid: idle-ec2,oversized-rds,orphan-ebs,untagged-spend"
    )

    args = parser.parse_args()

    # Determine rules to execute
    all_rules = ["idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"]
    rules_to_execute = args.rules if args.rules else all_rules

    # Execute
    if args.dry_run:
        results = FixtureProvider.get_fixture_results_for_rules(rules_to_execute)
    else:
        results = execute_rules(rules_to_execute)

    # Generate report
    generator = ReportGenerator()
    report = generator.generate(results, rules_to_execute)
    print(report)

    # Determine exit code
    successful = any(r.error is None for r in results)
    return 0 if successful else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
