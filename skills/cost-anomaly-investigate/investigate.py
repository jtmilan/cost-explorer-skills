"""
Cost Anomaly Investigation Skill

This module provides dataclass definitions and orchestration for investigating
AWS cost spikes by correlating Phase 1 cost data with CloudWatch metrics and
CloudTrail events.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List


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
