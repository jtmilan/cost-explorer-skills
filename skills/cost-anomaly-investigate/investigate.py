#!/usr/bin/env python3
"""
AWS Cost Anomaly Investigation Skill

Investigates the root causes of AWS cost spikes by correlating cost data
from Phase 1 (cost-explorer-query) with CloudWatch metrics and CloudTrail
events. Outputs a structured markdown report with spike size, likely causes,
and supporting evidence.

Module-Level Constants:
- SERVICE_TO_NAMESPACE: Maps AWS service names to CloudWatch namespaces
- SERVICE_TO_METRICS: Maps services to relevant CloudWatch metrics
- SERVICE_TO_RESOURCE_TYPE: Maps services to CloudTrail ResourceType strings
- CAUSE_DETECTION_THRESHOLDS: Heuristic thresholds for cause detection
- KNOWN_SERVICES: Set of valid service names (derived from SERVICE_TO_NAMESPACE)
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime, timezone, timedelta
import argparse
import sys
import re
import boto3
import botocore.exceptions


# ============================================================================
# Module-Level Constants
# ============================================================================

# Service-to-CloudWatch-Namespace mapping.
# Maps AWS service names (as entered via --service) to CloudWatch namespaces
# for metric retrieval.
#
# NOTE: Service names match Phase 1 query.py's service translation:
# - Phase 1 translates 'AmazonEC2' → 'EC2', 'AmazonRDS' → 'RDS', etc.
# - This mapping uses the TRANSLATED names, which align with investigate.py's
#   --service argument.
#
# INVARIANT: Every key in this dict must exist in both SERVICE_TO_METRICS
# and SERVICE_TO_RESOURCE_TYPE (enforced by unit tests).
SERVICE_TO_NAMESPACE: Dict[str, str] = {
    'EC2': 'AWS/EC2',
    'RDS': 'AWS/RDS',
    'Lambda': 'AWS/Lambda',
    'S3': 'AWS/S3',
    'DynamoDB': 'AWS/DynamoDB',
    'CloudFront': 'CloudFront',
    'ElasticSearch': 'AWS/ES',
    'Kinesis': 'AWS/Kinesis',
    'SNS': 'AWS/SNS',
    'SQS': 'AWS/SQS',
    'ECS': 'AWS/ECS',
    'EKS': 'AWS/EKS',
    # NOTE: AppFlow, Glue, and Batch REMOVED
    #       These services exist in Phase 1's cost data but lack:
    #       (a) Meaningful CloudWatch metrics suitable for cost spike investigation
    #       (b) Clear CloudTrail ResourceType mappings
    #       If needed in future, add corresponding entries to SERVICE_TO_METRICS
    #       and SERVICE_TO_RESOURCE_TYPE.
}

# Service-to-CloudWatch-Metrics mapping.
# For each service, lists the most relevant CloudWatch metrics to fetch.
# Metrics are service-level aggregations (not per-resource; pagination
# handled automatically).
#
# INVARIANT: All 12 services from SERVICE_TO_NAMESPACE must have entries here
# with non-empty metric lists.
SERVICE_TO_METRICS: Dict[str, List[str]] = {
    'EC2': ['CPUUtilization', 'NetworkIn', 'NetworkOut'],
    'RDS': ['DatabaseConnections', 'CPUUtilization', 'ReadIOPS', 'WriteIOPS'],
    'Lambda': ['Invocations', 'Errors', 'Duration', 'ConcurrentExecutions'],
    'S3': ['NumberOfObjects', 'BucketSizeBytes'],
    'DynamoDB': ['ConsumedReadCapacityUnits', 'ConsumedWriteCapacityUnits', 'UserErrors'],
    'CloudFront': ['Requests', 'BytesDownloaded', 'BytesUploaded'],
    'ElasticSearch': ['IndexingRate', 'SearchRate', 'CPUUtilization'],
    'Kinesis': ['GetRecords.IteratorAgeMilliseconds', 'ReadProvisionedThroughputExceeded'],
    'SNS': ['MessagePublished', 'NumberOfMessagesPublished'],
    'SQS': ['ApproximateNumberOfMessagesVisible', 'NumberOfSentMessages'],
    'ECS': ['MemoryUtilization', 'CPUUtilization'],
    'EKS': ['node_cpu_utilization', 'node_memory_utilization'],
}

# Service-to-CloudTrail-ResourceType mapping.
# Maps service names to CloudTrail ResourceType for filtering events.
# ResourceType values are AWS CloudTrail's official resource type strings
# (case-sensitive).
#
# INVARIANT: All 12 services from SERVICE_TO_NAMESPACE must have entries here.
SERVICE_TO_RESOURCE_TYPE: Dict[str, str] = {
    'EC2': 'AWS::EC2::Instance',
    'RDS': 'AWS::RDS::DBInstance',
    'Lambda': 'AWS::Lambda::Function',
    'S3': 'AWS::S3::Bucket',
    'DynamoDB': 'AWS::DynamoDB::Table',
    'CloudFront': 'AWS::CloudFront::Distribution',
    'ElasticSearch': 'AWS::Elasticsearch::Domain',
    'Kinesis': 'AWS::Kinesis::Stream',
    'SNS': 'AWS::SNS::Topic',
    'SQS': 'AWS::SQS::Queue',
    'ECS': 'AWS::ECS::Service',
    'EKS': 'AWS::EKS::Cluster',
}

# Cause detection thresholds (tunable constants).
# These thresholds drive the heuristic rules in cause detection.
# Each threshold is documented with its use case.
#
# - MIN_INSTANCE_LAUNCH_COUNT: If RunInstances event count >= this value,
#   flag as spike cause
# - MIN_TOTAL_EVENTS: If total mutating events >= this value, flag as
#   high activity
# - MIN_NETWORK_SPIKE_MBPS: If NetworkIn/Out spike >= this value in Mbps,
#   flag as anomaly
CAUSE_DETECTION_THRESHOLDS: Dict[str, int] = {
    'MIN_INSTANCE_LAUNCH_COUNT': 10,
    'MIN_TOTAL_EVENTS': 20,
    'MIN_NETWORK_SPIKE_MBPS': 50,
}

# Set of known AWS services (validated against --service argument).
# Derived from SERVICE_TO_NAMESPACE keys (source of truth).
#
# INVARIANT: Every key in SERVICE_TO_NAMESPACE must exist in both
# SERVICE_TO_METRICS and SERVICE_TO_RESOURCE_TYPE. This invariant is
# enforced by unit tests (test_constants_consistency).
KNOWN_SERVICES: Set[str] = set(SERVICE_TO_NAMESPACE.keys())


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SpikeSummary:
    """
    Summary of detected cost spike.

    Attributes:
        date: ISO 8601 date string (YYYY-MM-DD) being investigated
        service: AWS service name (e.g., 'EC2', 'RDS')
        baseline_cost: Average daily cost from previous month (USD float)
        spike_cost: Cost on spike date (USD float)
        delta: spike_cost - baseline_cost (USD float, may be negative if spike < baseline)
        delta_percent: (spike_cost - baseline_cost) / baseline_cost * 100 (percentage)
                       Special case: 0.0 if baseline_cost == 0.0 (undefined ratio)
    """
    date: str
    service: str
    baseline_cost: float
    spike_cost: float
    delta: float
    delta_percent: float


@dataclass
class MetricDatapoint:
    """
    Single metric observation from CloudWatch.

    Attributes:
        timestamp: UTC datetime of the metric sample
        value: Numeric value (e.g., 45.2 for CPUUtilization percentage)
        unit: CloudWatch unit string (e.g., 'Percent', 'Bytes', 'Count', 'None')
        statistic: The statistic retrieved (e.g., 'Average', 'Sum', 'Maximum')
    """
    timestamp: datetime
    value: float
    unit: str
    statistic: str


@dataclass
class CloudTrailEvent:
    """
    Single CloudTrail event (mutating action).

    Attributes:
        timestamp: UTC datetime of the API call
        principal: IAM principal ARN (e.g., 'arn:aws:iam::123456789012:user/alice')
        action: API action name (e.g., 'RunInstances', 'ModifyDBInstance')
        resource: List of resource ARNs affected by the action
                  (e.g., ['arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'])
        source_ip: Source IP address of the API call
    """
    timestamp: datetime
    principal: str
    action: str
    resource: List[str]
    source_ip: str


@dataclass
class LikelyCause:
    """
    Single hypothesis about cost spike root cause.

    Attributes:
        rank: Integer 1-3 (sorted by likelihood)
        title: Short title (e.g., "EC2 Instance Launch Surge")
        description: Longer explanation with evidence summary
        evidence_count: Number of supporting events/metrics
    """
    rank: int
    title: str
    description: str
    evidence_count: int


@dataclass
class InvestigationReport:
    """
    Complete investigation output before markdown rendering.

    Attributes:
        spike: SpikeSummary object
        metrics: Dict mapping metric_name -> List[MetricDatapoint]
                 (e.g., {'CPUUtilization': [datapoint1, datapoint2, ...], ...})
        events: List of CloudTrailEvent objects (filtered to mutating verbs)
        likely_causes: List of LikelyCause objects (1-3 items, sorted by rank)
        investigation_date: Investigation execution timestamp (UTC)
    """
    spike: SpikeSummary
    metrics: Dict[str, List[MetricDatapoint]]
    events: List[CloudTrailEvent]
    likely_causes: List[LikelyCause]
    investigation_date: datetime


# ============================================================================
# Validator Functions
# ============================================================================

def validate_date(date_str: str) -> str:
    r"""
    Validate date format YYYY-MM-DD strictly.

    Args:
        date_str: Date string to validate

    Returns:
        date_str if valid

    Raises:
        argparse.ArgumentTypeError: If format invalid or date is invalid
        (e.g., 2024-13-01, 2024-02-30, not a string)

    Implementation:
    1. Check format with regex: ^\d{4}-\d{2}-\d{2}$
    2. Parse to datetime to ensure valid calendar date
    3. Return date_str if both checks pass
    """
    # Check regex format
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        raise argparse.ArgumentTypeError(
            f"Date '{date_str}' does not match format YYYY-MM-DD"
        )

    # Parse to validate calendar date
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"Date '{date_str}' is not a valid calendar date: {e}"
        )

    return date_str


def validate_service(service_str: str) -> str:
    """
    Validate service name against KNOWN_SERVICES.

    Args:
        service_str: Service name (e.g., 'EC2', 'RDS')

    Returns:
        service_str if valid

    Raises:
        argparse.ArgumentTypeError: If not in KNOWN_SERVICES
        (e.g., 'UnknownService123', 'ec2' [case-sensitive])

    Implementation:
    1. Check if service_str in KNOWN_SERVICES
    2. Raise ArgumentTypeError with list of valid services if not found
    3. Return service_str if found
    """
    if service_str not in KNOWN_SERVICES:
        sorted_services = sorted(KNOWN_SERVICES)
        services_list = ', '.join(sorted_services)
        raise argparse.ArgumentTypeError(
            f"Service '{service_str}' is not recognized. "
            f"Valid services are: {services_list}"
        )

    return service_str


def parse_iso_date_to_utc(date_str: str) -> Tuple[datetime, datetime]:
    """
    Convert YYYY-MM-DD to UTC start/end times for 24-hour window.

    Args:
        date_str: Date in YYYY-MM-DD format (assumed valid from validate_date)

    Returns:
        Tuple of (start_utc, end_utc) datetime objects
        - start_utc: midnight (00:00:00) on the given date in UTC
        - end_utc: one second before midnight next day (23:59:59) in UTC

    Example:
        Input: "2024-03-15"
        Output: (
            datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc)
        )
    """
    # Parse the date string
    date_obj = datetime.strptime(date_str, '%Y-%m-%d')

    # Create timezone-aware datetime objects
    start_utc = date_obj.replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
    end_utc = date_obj.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)

    return (start_utc, end_utc)


def get_previous_month_range(date_str: str) -> Tuple[datetime, datetime]:
    """
    Get start and end dates of the previous calendar month.

    Args:
        date_str: Date in YYYY-MM-DD format

    Returns:
        Tuple of (start_date, end_date) as datetime objects (both at midnight UTC)
        - start_date: first day of previous month (00:00:00 UTC)
        - end_date: last day of previous month (00:00:00 UTC) [note: midnight of the NEXT day]

    Examples:
        Input: "2024-03-15" → Output: (datetime(2024, 2, 1), datetime(2024, 3, 1))
        Input: "2024-01-15" → Output: (datetime(2023, 12, 1), datetime(2024, 1, 1))

    Notes:
        - Handles year boundary (Jan 1 → Nov 1 of previous year)
        - Used for calculating baseline cost (previous month average)
    """
    # Parse the date string
    date_obj = datetime.strptime(date_str, '%Y-%m-%d')

    # Get first day of current month
    current_month_start = date_obj.replace(day=1, hour=0, minute=0, second=0, tzinfo=timezone.utc)

    # Get first day of previous month by subtracting one day from current month start
    previous_month_end = current_month_start - timedelta(days=1)
    previous_month_start = previous_month_end.replace(day=1)

    # Return as (start of prev month, start of current month)
    return (previous_month_start, current_month_start)
