"""
Tests for cost-anomaly-investigate investigate.py module.

Uses pytest to verify dataclass instantiation and field access for the five
dataclasses: SpikeSummary, MetricDatapoint, CloudTrailEvent, LikelyCause,
and InvestigationReport.

No AWS mocking required for these tests.
"""

import pytest
import sys
import os
from datetime import datetime, timezone
from typing import List, Dict
import importlib.util

# Load the investigate module directly from file
investigate_module_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'skills',
    'cost-anomaly-investigate',
    'investigate.py'
)

spec = importlib.util.spec_from_file_location("investigate", investigate_module_path)
investigate_module = importlib.util.module_from_spec(spec)
sys.modules['investigate'] = investigate_module
spec.loader.exec_module(investigate_module)

# Import the dataclasses under test
SpikeSummary = investigate_module.SpikeSummary
MetricDatapoint = investigate_module.MetricDatapoint
CloudTrailEvent = investigate_module.CloudTrailEvent
LikelyCause = investigate_module.LikelyCause
InvestigationReport = investigate_module.InvestigationReport


class TestDataclassInstantiation:
    """Test dataclass instantiation and field access."""

    def test_spike_summary_instantiation(self):
        """Test SpikeSummary dataclass instantiation with all fields."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=6434.56,
            delta=5234.56,
            delta_percent=435.3
        )

        assert spike.date == "2024-03-15"
        assert spike.service == "EC2"
        assert spike.baseline_cost == 1200.00
        assert spike.spike_cost == 6434.56
        assert spike.delta == 5234.56
        assert spike.delta_percent == 435.3

    def test_spike_summary_field_count(self):
        """Test SpikeSummary has exactly 6 fields."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=6434.56,
            delta=5234.56,
            delta_percent=435.3
        )
        # Check that the dataclass has exactly 6 fields
        fields = spike.__dataclass_fields__
        assert len(fields) == 6
        assert set(fields.keys()) == {
            'date', 'service', 'baseline_cost', 'spike_cost', 'delta', 'delta_percent'
        }

    def test_metric_datapoint_instantiation(self):
        """Test MetricDatapoint dataclass instantiation with all fields."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        datapoint = MetricDatapoint(
            timestamp=timestamp,
            value=45.2,
            unit="Percent",
            statistic="Average"
        )

        assert datapoint.timestamp == timestamp
        assert datapoint.value == 45.2
        assert datapoint.unit == "Percent"
        assert datapoint.statistic == "Average"

    def test_metric_datapoint_field_count(self):
        """Test MetricDatapoint has exactly 4 fields."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        datapoint = MetricDatapoint(
            timestamp=timestamp,
            value=45.2,
            unit="Percent",
            statistic="Average"
        )
        # Check that the dataclass has exactly 4 fields
        fields = datapoint.__dataclass_fields__
        assert len(fields) == 4
        assert set(fields.keys()) == {'timestamp', 'value', 'unit', 'statistic'}

    def test_cloudtrail_event_instantiation(self):
        """Test CloudTrailEvent dataclass instantiation with all fields."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        event = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:user/alice",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            source_ip="203.0.113.42"
        )

        assert event.timestamp == timestamp
        assert event.principal == "arn:aws:iam::123456789012:user/alice"
        assert event.action == "RunInstances"
        assert event.resource == ["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"]
        assert event.source_ip == "203.0.113.42"

    def test_cloudtrail_event_multiple_resources(self):
        """Test CloudTrailEvent with multiple resources."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        resources = [
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-0987654321fedcba0"
        ]
        event = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:role/lambda-role",
            action="RunInstances",
            resource=resources,
            source_ip="203.0.113.42"
        )

        assert event.resource == resources
        assert len(event.resource) == 2

    def test_cloudtrail_event_field_count(self):
        """Test CloudTrailEvent has exactly 5 fields."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        event = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:user/alice",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            source_ip="203.0.113.42"
        )
        # Check that the dataclass has exactly 5 fields
        fields = event.__dataclass_fields__
        assert len(fields) == 5
        assert set(fields.keys()) == {'timestamp', 'principal', 'action', 'resource', 'source_ip'}

    def test_likely_cause_instantiation(self):
        """Test LikelyCause dataclass instantiation with all fields."""
        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="15 instances launched on 2024-03-15",
            evidence_count=15
        )

        assert cause.rank == 1
        assert cause.title == "EC2 Instance Launch Surge"
        assert cause.description == "15 instances launched on 2024-03-15"
        assert cause.evidence_count == 15

    def test_likely_cause_field_count(self):
        """Test LikelyCause has exactly 4 fields."""
        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="15 instances launched on 2024-03-15",
            evidence_count=15
        )
        # Check that the dataclass has exactly 4 fields
        fields = cause.__dataclass_fields__
        assert len(fields) == 4
        assert set(fields.keys()) == {'rank', 'title', 'description', 'evidence_count'}

    def test_investigation_report_instantiation(self):
        """Test InvestigationReport dataclass instantiation with all fields."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=6434.56,
            delta=5234.56,
            delta_percent=435.3
        )

        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        datapoint = MetricDatapoint(
            timestamp=timestamp,
            value=45.2,
            unit="Percent",
            statistic="Average"
        )
        metrics = {"CPUUtilization": [datapoint]}

        event = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:user/alice",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            source_ip="203.0.113.42"
        )
        events = [event]

        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="15 instances launched on 2024-03-15",
            evidence_count=15
        )
        likely_causes = [cause]

        investigation_date = datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc)

        report = InvestigationReport(
            spike=spike,
            metrics=metrics,
            events=events,
            likely_causes=likely_causes,
            investigation_date=investigation_date
        )

        assert report.spike == spike
        assert report.metrics == metrics
        assert report.events == events
        assert report.likely_causes == likely_causes
        assert report.investigation_date == investigation_date

    def test_investigation_report_field_count(self):
        """Test InvestigationReport has exactly 5 fields."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=6434.56,
            delta=5234.56,
            delta_percent=435.3
        )

        report = InvestigationReport(
            spike=spike,
            metrics={},
            events=[],
            likely_causes=[],
            investigation_date=datetime.now(timezone.utc)
        )

        # Check that the dataclass has exactly 5 fields
        fields = report.__dataclass_fields__
        assert len(fields) == 5
        assert set(fields.keys()) == {
            'spike', 'metrics', 'events', 'likely_causes', 'investigation_date'
        }

    def test_investigation_report_with_multiple_metrics_and_events(self):
        """Test InvestigationReport with multiple metrics and events."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=6434.56,
            delta=5234.56,
            delta_percent=435.3
        )

        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        datapoint1 = MetricDatapoint(
            timestamp=timestamp,
            value=45.2,
            unit="Percent",
            statistic="Average"
        )
        datapoint2 = MetricDatapoint(
            timestamp=timestamp,
            value=89.5,
            unit="Percent",
            statistic="Maximum"
        )
        metrics = {
            "CPUUtilization": [datapoint1, datapoint2],
            "NetworkIn": [datapoint1]
        }

        event1 = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:user/alice",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            source_ip="203.0.113.42"
        )
        event2 = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:role/lambda-role",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-0987654321fedcba0"],
            source_ip="203.0.113.43"
        )
        events = [event1, event2]

        cause1 = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="15 instances launched on 2024-03-15",
            evidence_count=15
        )
        cause2 = LikelyCause(
            rank=2,
            title="Data Transfer Spike",
            description="NetworkOut exceeded 100 Mbps",
            evidence_count=10
        )
        likely_causes = [cause1, cause2]

        investigation_date = datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc)

        report = InvestigationReport(
            spike=spike,
            metrics=metrics,
            events=events,
            likely_causes=likely_causes,
            investigation_date=investigation_date
        )

        assert len(report.metrics) == 2
        assert "CPUUtilization" in report.metrics
        assert "NetworkIn" in report.metrics
        assert len(report.metrics["CPUUtilization"]) == 2
        assert len(report.events) == 2
        assert len(report.likely_causes) == 2

    def test_all_dataclasses_are_dataclasses(self):
        """Verify that all classes are dataclasses with @dataclass decorator."""
        # Verify each class has __dataclass_fields__
        assert hasattr(SpikeSummary, '__dataclass_fields__')
        assert hasattr(MetricDatapoint, '__dataclass_fields__')
        assert hasattr(CloudTrailEvent, '__dataclass_fields__')
        assert hasattr(LikelyCause, '__dataclass_fields__')
        assert hasattr(InvestigationReport, '__dataclass_fields__')

    def test_type_hints_spike_summary(self):
        """Verify SpikeSummary field type hints."""
        annotations = SpikeSummary.__annotations__
        assert annotations['date'] == str
        assert annotations['service'] == str
        assert annotations['baseline_cost'] == float
        assert annotations['spike_cost'] == float
        assert annotations['delta'] == float
        assert annotations['delta_percent'] == float

    def test_type_hints_metric_datapoint(self):
        """Verify MetricDatapoint field type hints."""
        annotations = MetricDatapoint.__annotations__
        assert annotations['timestamp'] == datetime
        assert annotations['value'] == float
        assert annotations['unit'] == str
        assert annotations['statistic'] == str

    def test_type_hints_cloudtrail_event(self):
        """Verify CloudTrailEvent field type hints."""
        annotations = CloudTrailEvent.__annotations__
        assert annotations['timestamp'] == datetime
        assert annotations['principal'] == str
        assert annotations['action'] == str
        assert annotations['resource'] == List[str]
        assert annotations['source_ip'] == str

    def test_type_hints_likely_cause(self):
        """Verify LikelyCause field type hints."""
        annotations = LikelyCause.__annotations__
        assert annotations['rank'] == int
        assert annotations['title'] == str
        assert annotations['description'] == str
        assert annotations['evidence_count'] == int

    def test_type_hints_investigation_report(self):
        """Verify InvestigationReport field type hints."""
        annotations = InvestigationReport.__annotations__
        assert annotations['spike'] == SpikeSummary
        assert annotations['metrics'] == Dict[str, List[MetricDatapoint]]
        assert annotations['events'] == List[CloudTrailEvent]
        assert annotations['likely_causes'] == List[LikelyCause]
        assert annotations['investigation_date'] == datetime

    def test_spike_summary_with_zero_baseline(self):
        """Test SpikeSummary with baseline_cost = 0.0 (edge case)."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=0.0,
            spike_cost=6434.56,
            delta=6434.56,
            delta_percent=0.0  # Undefined ratio; set to 0.0
        )

        assert spike.baseline_cost == 0.0
        assert spike.delta_percent == 0.0

    def test_spike_summary_negative_delta(self):
        """Test SpikeSummary with negative delta (cost decrease)."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=600.00,
            delta=-600.00,
            delta_percent=-50.0
        )

        assert spike.delta < 0
        assert spike.delta_percent < 0
