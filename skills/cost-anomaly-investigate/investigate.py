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


# ============================================================================
# CostAnomalyInvestigator Class
# ============================================================================

class CostAnomalyInvestigator:
    """
    Orchestrates cost spike investigation via Phase 1, CloudWatch, and CloudTrail.

    Does NOT perform validation; assumes caller has validated date and service.
    Propagates all AWS exceptions (NoCredentialsError, ClientError) to caller.
    """

    def __init__(self, date: str, service: str):
        """
        Initialize investigator.

        Args:
            date: YYYY-MM-DD string (assumed valid from validate_date)
            service: AWS service name (assumed valid from validate_service)

        Raises:
            botocore.exceptions.NoCredentialsError: If boto3 cannot find credentials
        """
        self.date = date
        self.service = service
        # Lazy initialization of AWS clients (on first use, not in __init__)
        self._ce_client = None
        self._cloudwatch = None
        self._cloudtrail = None

    def detect_spike(self) -> SpikeSummary:
        """
        Detect cost spike using Phase 1 query.py.

        Compares spike_date cost to previous month average:
        - baseline = average daily cost of previous calendar month
        - spike = cost on target date
        - delta = spike - baseline
        - delta_percent = (delta / baseline * 100) if baseline > 0 else 0.0

        Edge Case (Previous Month Unavailable):
        If previous month has zero data:
          - baseline_cost = 0.0
          - delta_percent = 0.0 (undefined ratio)
          - Any spike_cost > 0 is treated as a spike (delta > 0)
          - Caller should note "No baseline available" in report

        Returns:
            SpikeSummary object with spike details

        Raises:
            botocore.exceptions.NoCredentialsError: If credentials missing
            botocore.exceptions.ClientError: If Cost Explorer API fails
            ValueError: If date parsing fails (shouldn't happen; caller validated)
        """
        # Import here to avoid circular imports
        # Note: Module name has hyphen, but import uses underscore via importlib
        import importlib
        query_module = importlib.import_module('skills.cost-explorer-query.query')
        CostExplorerClient = query_module.CostExplorerClient

        # Get previous month range for baseline
        prev_start, prev_end = get_previous_month_range(self.date)

        # Query previous month costs
        ce_client = CostExplorerClient()
        prev_results = ce_client.get_costs(
            start_date=prev_start.strftime('%Y-%m-%d'),
            end_date=prev_end.strftime('%Y-%m-%d'),
            group_by='service'
        )

        # Calculate baseline (average daily cost of previous month)
        prev_total = sum(cost for service, cost in prev_results if service == self.service)

        # Get number of days in previous month
        prev_month_end = prev_end - timedelta(days=1)
        days_in_prev_month = prev_month_end.day
        baseline_cost = prev_total / days_in_prev_month if prev_total > 0 else 0.0

        # Query spike date costs
        spike_start, spike_end = parse_iso_date_to_utc(self.date)
        spike_results = ce_client.get_costs(
            start_date=self.date,
            end_date=self.date,
            group_by='service'
        )

        spike_cost = next(
            (cost for service, cost in spike_results if service == self.service),
            0.0
        )

        # Calculate delta and delta_percent
        delta = spike_cost - baseline_cost
        delta_percent = (delta / baseline_cost * 100) if baseline_cost > 0 else 0.0

        return SpikeSummary(
            date=self.date,
            service=self.service,
            baseline_cost=baseline_cost,
            spike_cost=spike_cost,
            delta=delta,
            delta_percent=delta_percent
        )

    def get_cloudwatch_metrics(self) -> Dict[str, List[MetricDatapoint]]:
        """
        Fetch CloudWatch metrics for the spike date (24-hour window, 00:00-23:59 UTC).

        Returns dict of metric_name -> list of MetricDatapoint objects.
        - Metric names are from SERVICE_TO_METRICS[self.service]
        - Datapoints are fetched with granularity=60 seconds (standard for CloudWatch)
        - Empty metrics (no data available) are omitted from the result dict

        Returns:
            Dict mapping metric_name (str) → List[MetricDatapoint]
            Example: {
                'CPUUtilization': [MetricDatapoint(...), MetricDatapoint(...), ...],
                'NetworkIn': [MetricDatapoint(...), ...]
            }
            May be empty if no metrics available for the service on that date.

        Raises:
            botocore.exceptions.NoCredentialsError: If credentials missing
            botocore.exceptions.ClientError: If CloudWatch API fails
        """
        if self._cloudwatch is None:
            self._cloudwatch = boto3.client('cloudwatch', region_name='us-east-1')

        # Parse date to UTC start/end times (00:00:00 - 23:59:59 UTC)
        start_time, end_time = parse_iso_date_to_utc(self.date)

        # Get namespace for this service
        namespace = SERVICE_TO_NAMESPACE[self.service]

        # Get metric names to fetch
        metric_names = SERVICE_TO_METRICS[self.service]

        results = {}

        for metric_name in metric_names:
            try:
                response = self._cloudwatch.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=60,  # 60-second granularity
                    Statistics=['Average', 'Sum', 'Maximum']
                )

                # Parse datapoints
                datapoints = []
                for dp in response.get('Datapoints', []):
                    # Extract the primary statistic (Average preferred, then Sum, then Maximum)
                    if 'Average' in dp:
                        value = float(dp['Average'])
                        statistic = 'Average'
                    elif 'Sum' in dp:
                        value = float(dp['Sum'])
                        statistic = 'Sum'
                    elif 'Maximum' in dp:
                        value = float(dp['Maximum'])
                        statistic = 'Maximum'
                    else:
                        continue

                    datapoint = MetricDatapoint(
                        timestamp=dp['Timestamp'],
                        value=value,
                        unit=dp.get('Unit', 'None'),
                        statistic=statistic
                    )
                    datapoints.append(datapoint)

                # Only add to results if we got data
                if datapoints:
                    results[metric_name] = sorted(datapoints, key=lambda x: x.timestamp)

            except botocore.exceptions.ClientError as e:
                # Gracefully skip metrics that don't exist or can't be fetched
                continue

        return results

    def get_cloudtrail_events(self) -> List[CloudTrailEvent]:
        """
        Fetch CloudTrail events for spike date filtered to mutating verbs.

        Calls CloudTrail LookupEvents API with:
        - ResourceType filter = SERVICE_TO_RESOURCE_TYPE[self.service]
        - Date range = 24-hour window (00:00-23:59 UTC) on self.date
        - EventName regex filter = (Create.*|Modify.*|Delete.*|Update.*|Put.*|Post.*)
          (excludes Get*, Describe*, List* read-only operations)

        Returns:
            List of CloudTrailEvent objects (sorted by timestamp, oldest first)
            Empty list if no mutating events found on the date.

        Raises:
            botocore.exceptions.NoCredentialsError: If credentials missing
            botocore.exceptions.ClientError: If CloudTrail API fails
        """
        if self._cloudtrail is None:
            self._cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')

        # Parse date to UTC start/end times
        start_time, end_time = parse_iso_date_to_utc(self.date)

        # Get resource type for this service
        resource_type = SERVICE_TO_RESOURCE_TYPE[self.service]

        results = []
        next_token = None

        # Regex pattern for mutating verbs
        mutating_pattern = re.compile(r'^(Create|Modify|Delete|Update|Put|Post).*')

        while True:
            # Build request
            request = {
                'LookupAttributes': [
                    {
                        'AttributeKey': 'ResourceType',
                        'AttributeValue': resource_type
                    }
                ],
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': 50  # pagination
            }

            if next_token:
                request['NextToken'] = next_token

            # Call API
            response = self._cloudtrail.lookup_events(**request)

            # Parse events and filter to mutating verbs
            for event in response.get('Events', []):
                event_name = event.get('EventName', '')

                # Filter to mutating verbs only
                if not mutating_pattern.match(event_name):
                    continue

                # Parse CloudTrailEvent
                # CloudTrail API returns Resources with ResourceName and ResourceType
                resources = event.get('Resources', [])
                resource_arns = []
                if resources:
                    for r in resources:
                        # Try to construct ARN from ResourceName if available
                        resource_name = r.get('ResourceName', '')
                        if resource_name:
                            resource_arns.append(resource_name)

                ct_event = CloudTrailEvent(
                    timestamp=event.get('EventTime'),
                    principal=event.get('Username', ''),
                    action=event_name,
                    resource=resource_arns,
                    source_ip=event.get('SourceIPAddress', '') or ''
                )
                results.append(ct_event)

            # Check for pagination
            next_token = response.get('NextToken')
            if not next_token:
                break

        # Sort by timestamp ascending
        results.sort(key=lambda x: x.timestamp)

        return results

    def investigate(self) -> InvestigationReport:
        """
        Orchestrate spike detection, metrics retrieval, and event gathering.

        Calls detect_spike(), get_cloudwatch_metrics(), get_cloudtrail_events() in sequence.
        Then invokes _derive_causes() to generate likely-cause hypotheses.

        Returns:
            InvestigationReport with all data assembled

        Raises:
            Any exception from detect_spike(), get_cloudwatch_metrics(), get_cloudtrail_events()
            (propagated to caller)
        """
        # Call detect_spike
        spike = self.detect_spike()

        # Call get_cloudwatch_metrics
        metrics = self.get_cloudwatch_metrics()

        # Call get_cloudtrail_events
        events = self.get_cloudtrail_events()

        # Call _derive_causes
        likely_causes = self._derive_causes(spike, metrics, events)

        # Return InvestigationReport
        return InvestigationReport(
            spike=spike,
            metrics=metrics,
            events=events,
            likely_causes=likely_causes,
            investigation_date=datetime.now(timezone.utc)
        )

    def _derive_causes(
        self,
        spike: SpikeSummary,
        metrics: Dict[str, List[MetricDatapoint]],
        events: List[CloudTrailEvent]
    ) -> List[LikelyCause]:
        """
        Heuristic rule-based matching to derive likely causes.

        Applies rules in order of specificity; returns 1-3 LikelyCause objects.

        Rules (applied in order; each rule has a threshold and generates a cause hypothesis):
        1. EC2 Instance Launch Surge: If events contains >= 10 RunInstances actions
           → Cause: "EC2 instance launch surge (X instances launched)"
        2. Database Scaling: If events contains ModifyDBInstance or CreateDBInstance
           → Cause: "Database scaling or provisioning change"
        3. Data Transfer Spike: If metrics contains NetworkIn or NetworkOut with spike > 50 Mbps
           → Cause: "Unexpected data transfer volume"
        4. High Mutation Rate: If total events >= 20
           → Cause: "Configuration or deployment activity (X mutating events)"
        5. Fallback: "Unable to determine root cause; review metrics and events for patterns"

        Each rule generates one LikelyCause object. If multiple rules match, return up to 3 most likely.
        Order LikelyCause objects by rank (1=most likely, 3=least likely).

        Returns:
            List[LikelyCause] with 1-3 items (never empty; fallback always applied)
        """
        causes = []

        # Rule 1: EC2 Instance Launch Surge
        run_instances_count = sum(1 for e in events if e.action == 'RunInstances')
        if run_instances_count >= CAUSE_DETECTION_THRESHOLDS['MIN_INSTANCE_LAUNCH_COUNT']:
            causes.append(LikelyCause(
                rank=len(causes) + 1,
                title="EC2 instance launch surge",
                description=f"{run_instances_count} instances launched on {spike.date}",
                evidence_count=run_instances_count
            ))

        # Rule 2: Database Scaling
        db_events = [e for e in events if e.action in ['ModifyDBInstance', 'CreateDBInstance']]
        if db_events:
            causes.append(LikelyCause(
                rank=len(causes) + 1,
                title="Database scaling or provisioning change",
                description=f"Database instances modified or created ({len(db_events)} events)",
                evidence_count=len(db_events)
            ))

        # Rule 3: Data Transfer Spike
        network_metrics = {k: v for k, v in metrics.items() if 'Network' in k or 'Bytes' in k}
        if network_metrics:
            for metric_name, datapoints in network_metrics.items():
                if datapoints:
                    max_value = max(dp.value for dp in datapoints)
                    # Check if NetworkOut spike > 50 Mbps (simple heuristic)
                    if max_value > CAUSE_DETECTION_THRESHOLDS['MIN_NETWORK_SPIKE_MBPS']:
                        causes.append(LikelyCause(
                            rank=len(causes) + 1,
                            title="Unexpected data transfer volume",
                            description=f"{metric_name} exceeded {CAUSE_DETECTION_THRESHOLDS['MIN_NETWORK_SPIKE_MBPS']} units",
                            evidence_count=len(datapoints)
                        ))
                        break  # Only add this cause once

        # Rule 4: High Mutation Rate
        if len(events) >= CAUSE_DETECTION_THRESHOLDS['MIN_TOTAL_EVENTS']:
            causes.append(LikelyCause(
                rank=len(causes) + 1,
                title="Configuration or deployment activity",
                description=f"{len(events)} mutating events detected on {spike.date}",
                evidence_count=len(events)
            ))

        # Ensure we always have at least 1 cause (Rule 5: Fallback)
        if not causes:
            causes.append(LikelyCause(
                rank=1,
                title="Unable to determine root cause",
                description="Review metrics and events for patterns",
                evidence_count=0
            ))

        # Limit to 3 causes and update ranks
        causes = causes[:3]
        for i, cause in enumerate(causes, start=1):
            cause.rank = i

        return causes


# ============================================================================
# ReportGenerator Class
# ============================================================================

class ReportGenerator:
    """
    Converts InvestigationReport data into markdown report string.
    """

    def generate(self, report: InvestigationReport) -> str:
        """
        Generate markdown report from InvestigationReport.

        Returns:
            Multi-line markdown string with fixed structure:
            1. Header: "# Cost Spike: $X,XXX on YYYY-MM-DD (SERVICE)"
            2. Spike Summary section: Baseline vs. spike cost, delta, delta_percent
            3. Likely Causes section: 1-3 cause items (numbered)
            4. Evidence section: CloudTrail events + metrics summary
            5. Footer: "Investigation completed at TIMESTAMP"
        """
        # Build sections
        header = self._format_spike_header(report.spike)
        summary = self._format_spike_summary(report.spike)
        causes = self._format_causes(report.likely_causes)
        events = self._format_cloudtrail_events(report.events)
        metrics = self._format_metrics_summary(report.metrics)
        footer = self._format_footer(report.investigation_date)

        # Combine all sections with proper spacing
        sections = [
            header,
            '',
            summary,
            '',
            causes,
            '',
            '## Evidence',
            '',
            events,
            '',
            metrics,
            '',
            footer
        ]

        return '\n'.join(sections)

    def _format_spike_header(self, spike: SpikeSummary) -> str:
        """
        Format spike header line: "# Cost Spike: $X,XXX on YYYY-MM-DD (SERVICE)"
        """
        return f"# Cost Spike: ${spike.delta:,.2f} on {spike.date} ({spike.service})"

    def _format_spike_summary(self, spike: SpikeSummary) -> str:
        """
        Format spike summary block.
        """
        lines = ["## Spike Summary"]

        if spike.baseline_cost == 0.0:
            lines.append("No baseline available (previous month has no data)")
        else:
            lines.append(f"Baseline (previous month average): ${spike.baseline_cost:,.2f}/day")

        lines.append(f"Spike cost ({spike.date}): ${spike.spike_cost:,.2f}/day")

        if spike.baseline_cost > 0:
            change_label = "increase" if spike.delta > 0 else "decrease"
            lines.append(f"Delta: ${abs(spike.delta):,.2f} ({abs(spike.delta_percent):.1f}% {change_label})")
        else:
            if spike.spike_cost > 0:
                lines.append(f"Delta: ${spike.spike_cost:,.2f}")

        return '\n'.join(lines)

    def _format_causes(self, causes: List[LikelyCause]) -> str:
        """
        Format likely causes section.
        """
        lines = ["## Likely Causes"]

        for cause in causes:
            lines.append(f"{cause.rank}. {cause.title}: {cause.description}")

        return '\n'.join(lines)

    def _format_cloudtrail_events(self, events: List[CloudTrailEvent]) -> str:
        """
        Format CloudTrail events as markdown table or message.
        """
        lines = ["### CloudTrail Events"]

        if not events:
            lines.append("No mutating events found on this date.")
            return '\n'.join(lines)

        # Build table header
        lines.append("| Timestamp | Principal | Action | Resources |")
        lines.append("|-----------|-----------|--------|-----------|")

        # Add event rows
        for event in events:
            timestamp_str = event.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')

            # Truncate principal if too long
            principal = event.principal
            if len(principal) > 50:
                principal = principal[:47] + "..."

            # Join multiple resources with comma
            resources_str = ', '.join(event.resource) if event.resource else ''

            lines.append(
                f"| {timestamp_str} | {principal} | {event.action} | {resources_str} |"
            )

        return '\n'.join(lines)

    def _format_metrics_summary(self, metrics: Dict[str, List[MetricDatapoint]]) -> str:
        """
        Format metrics summary (brief, not exhaustive).
        """
        lines = ["### Metrics"]

        if not metrics:
            lines.append("No metrics available for this service on this date.")
            return '\n'.join(lines)

        # Sort metrics alphabetically
        for metric_name in sorted(metrics.keys()):
            datapoints = metrics[metric_name]
            if not datapoints:
                continue

            # Extract values by statistic
            stats_dict = {}
            for dp in datapoints:
                stat = dp.statistic
                if stat not in stats_dict:
                    stats_dict[stat] = []
                stats_dict[stat].append(dp.value)

            # Build metric line
            parts = [metric_name + ":"]

            # Average
            if 'Average' in stats_dict:
                avg_val = sum(stats_dict['Average']) / len(stats_dict['Average'])
                unit = self._normalize_unit(metrics[metric_name][0].unit)
                if unit:
                    parts.append(f"{avg_val:.1f}{unit} average")
                else:
                    parts.append(f"{avg_val:.1f} average")

            # Maximum
            if 'Maximum' in stats_dict:
                max_val = max(stats_dict['Maximum'])
                unit = self._normalize_unit(metrics[metric_name][0].unit)
                if unit:
                    parts.append(f"max {max_val:.1f}{unit}")
                else:
                    parts.append(f"max {max_val:.1f}")

            # Sum (for aggregated metrics)
            if 'Sum' in stats_dict and 'Average' not in stats_dict:
                sum_val = sum(stats_dict['Sum'])
                unit = self._normalize_unit(metrics[metric_name][0].unit)
                if unit:
                    parts.append(f"{sum_val:.1f}{unit} total")
                else:
                    parts.append(f"{sum_val:.1f} total")

            lines.append(' '.join(parts) + ',')

        # Remove trailing commas and clean up
        if lines[-1].endswith(','):
            lines[-1] = lines[-1][:-1]

        return '\n'.join(lines)

    def _normalize_unit(self, unit: str) -> str:
        """
        Normalize CloudWatch unit to short form.
        """
        if unit == 'Percent':
            return '%'
        elif unit == 'Bytes':
            return ' GB'  # Note: values should be divided by 1e9 by caller
        elif unit == 'Count' or unit == 'None':
            return ''
        else:
            return ''

    def _format_footer(self, investigation_date: datetime) -> str:
        """
        Format footer with investigation timestamp.
        """
        timestamp_str = investigation_date.strftime('%Y-%m-%dT%H:%M:%SZ')
        return f"---\nInvestigation completed at {timestamp_str}"


# ============================================================================
# FixtureProvider Class
# ============================================================================

class FixtureProvider:
    """
    Provides deterministic fixture data for --dry-run mode.
    No AWS calls; returns hardcoded markdown report.
    """

    @staticmethod
    def get_fixture_report() -> str:
        """
        Return deterministic markdown report for testing.

        Returns:
            Multi-line markdown string (identical on every invocation)
            Fixture matches the exact structure generated by ReportGenerator.generate()
        """
        return """\
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
CPUUtilization: 45.2% average, max 89.5%,
NetworkIn: 1.2 GB total,
NetworkOut: 2.5 GB total

---
Investigation completed at 2024-03-15T14:30:00Z"""
