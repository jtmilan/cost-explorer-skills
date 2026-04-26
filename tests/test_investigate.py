"""
Tests for cost-anomaly-investigate investigate.py module.

Tests cover:
- Dataclass instantiation and field access (SpikeSummary, MetricDatapoint, CloudTrailEvent, LikelyCause, InvestigationReport)
- Module-level constants consistency (SERVICE_TO_NAMESPACE, SERVICE_TO_METRICS, SERVICE_TO_RESOURCE_TYPE)
- CAUSE_DETECTION_THRESHOLDS presence
- KNOWN_SERVICES correctness
- Service invariants (no missing keys, excluded services not present)
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

# Import the constants under test
SERVICE_TO_NAMESPACE = investigate_module.SERVICE_TO_NAMESPACE
SERVICE_TO_METRICS = investigate_module.SERVICE_TO_METRICS
SERVICE_TO_RESOURCE_TYPE = investigate_module.SERVICE_TO_RESOURCE_TYPE
CAUSE_DETECTION_THRESHOLDS = investigate_module.CAUSE_DETECTION_THRESHOLDS
KNOWN_SERVICES = investigate_module.KNOWN_SERVICES


# ============================================================================
# Tests for Dataclass Instantiation
# ============================================================================

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
            source_ip="192.0.2.1"
        )

        assert event.timestamp == timestamp
        assert event.principal == "arn:aws:iam::123456789012:user/alice"
        assert event.action == "RunInstances"
        assert event.resource == ["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"]
        assert event.source_ip == "192.0.2.1"

    def test_cloudtrail_event_field_count(self):
        """Test CloudTrailEvent has exactly 5 fields."""
        timestamp = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        event = CloudTrailEvent(
            timestamp=timestamp,
            principal="arn:aws:iam::123456789012:user/alice",
            action="RunInstances",
            resource=["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            source_ip="192.0.2.1"
        )
        fields = event.__dataclass_fields__
        assert len(fields) == 5
        assert set(fields.keys()) == {'timestamp', 'principal', 'action', 'resource', 'source_ip'}

    def test_likely_cause_instantiation(self):
        """Test LikelyCause dataclass instantiation with all fields."""
        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="3 RunInstances events detected",
            evidence_count=3
        )

        assert cause.rank == 1
        assert cause.title == "EC2 Instance Launch Surge"
        assert cause.description == "3 RunInstances events detected"
        assert cause.evidence_count == 3

    def test_likely_cause_field_count(self):
        """Test LikelyCause has exactly 4 fields."""
        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="3 RunInstances events detected",
            evidence_count=3
        )
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

        cause = LikelyCause(
            rank=1,
            title="EC2 Instance Launch Surge",
            description="3 RunInstances events detected",
            evidence_count=3
        )

        investigation_date = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = InvestigationReport(
            spike=spike,
            metrics={"CPUUtilization": [datapoint]},
            events=[],
            likely_causes=[cause],
            investigation_date=investigation_date
        )

        assert report.spike == spike
        assert report.metrics == {"CPUUtilization": [datapoint]}
        assert report.events == []
        assert report.likely_causes == [cause]
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
        investigation_date = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = InvestigationReport(
            spike=spike,
            metrics={},
            events=[],
            likely_causes=[],
            investigation_date=investigation_date
        )
        fields = report.__dataclass_fields__
        assert len(fields) == 5
        assert set(fields.keys()) == {'spike', 'metrics', 'events', 'likely_causes', 'investigation_date'}


# ============================================================================
# Tests for Edge Cases
# ============================================================================

class TestDataclassEdgeCases:
    """Test edge cases for dataclass instantiation."""

    def test_spike_summary_zero_baseline_cost(self):
        """Test SpikeSummary handles zero baseline cost (undefined ratio case)."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=0.0,
            spike_cost=100.0,
            delta=100.0,
            delta_percent=0.0
        )
        assert spike.baseline_cost == 0.0
        assert spike.delta_percent == 0.0

    def test_spike_summary_negative_delta(self):
        """Test SpikeSummary handles negative delta (spike < baseline)."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="EC2",
            baseline_cost=1200.00,
            spike_cost=800.00,
            delta=-400.00,
            delta_percent=-33.33
        )
        assert spike.delta == -400.00
        assert spike.delta_percent == -33.33

    def test_cloudtrail_event_multiple_resources(self):
        """Test CloudTrailEvent handles multiple affected resources."""
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
            source_ip="192.0.2.1"
        )
        assert len(event.resource) == 2
        assert event.resource == resources

    def test_investigation_report_empty_collections(self):
        """Test InvestigationReport with empty metrics, events, and causes."""
        spike = SpikeSummary(
            date="2024-03-15",
            service="S3",
            baseline_cost=500.00,
            spike_cost=500.00,
            delta=0.0,
            delta_percent=0.0
        )
        investigation_date = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = InvestigationReport(
            spike=spike,
            metrics={},
            events=[],
            likely_causes=[],
            investigation_date=investigation_date
        )
        assert report.metrics == {}
        assert report.events == []
        assert report.likely_causes == []


# ============================================================================
# Tests for Module-Level Constants
# ============================================================================

class TestServiceToNamespace:
    """Test SERVICE_TO_NAMESPACE constant."""

    def test_service_to_namespace_has_exactly_12_services(self):
        """SERVICE_TO_NAMESPACE must contain exactly 12 services."""
        assert len(SERVICE_TO_NAMESPACE) == 12

    def test_service_to_namespace_contains_all_required_services(self):
        """Verify all 12 required services are present."""
        required_services = {
            'EC2', 'RDS', 'Lambda', 'S3', 'DynamoDB', 'CloudFront',
            'ElasticSearch', 'Kinesis', 'SNS', 'SQS', 'ECS', 'EKS'
        }
        assert set(SERVICE_TO_NAMESPACE.keys()) == required_services

    def test_service_to_namespace_uses_correct_strings(self):
        """Verify CloudWatch namespace strings match architecture exactly."""
        expected = {
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
        }
        assert SERVICE_TO_NAMESPACE == expected

    def test_service_to_namespace_excluded_services_not_present(self):
        """AppFlow, Glue, Batch must NOT be in SERVICE_TO_NAMESPACE."""
        assert 'AppFlow' not in SERVICE_TO_NAMESPACE
        assert 'Glue' not in SERVICE_TO_NAMESPACE
        assert 'Batch' not in SERVICE_TO_NAMESPACE


class TestServiceToMetrics:
    """Test SERVICE_TO_METRICS constant."""

    def test_service_to_metrics_has_all_12_services(self):
        """SERVICE_TO_METRICS must have entries for all 12 services."""
        assert len(SERVICE_TO_METRICS) == 12

    def test_service_to_metrics_contains_all_required_services(self):
        """Verify all 12 required services have metric mappings."""
        required_services = {
            'EC2', 'RDS', 'Lambda', 'S3', 'DynamoDB', 'CloudFront',
            'ElasticSearch', 'Kinesis', 'SNS', 'SQS', 'ECS', 'EKS'
        }
        assert set(SERVICE_TO_METRICS.keys()) == required_services

    def test_service_to_metrics_all_entries_non_empty(self):
        """Each service must have a non-empty metric list."""
        for service, metrics in SERVICE_TO_METRICS.items():
            assert isinstance(metrics, list), f"{service} metrics must be a list"
            assert len(metrics) > 0, f"{service} must have at least one metric"

    def test_service_to_metrics_all_metrics_are_strings(self):
        """All metric names must be strings."""
        for service, metrics in SERVICE_TO_METRICS.items():
            for metric in metrics:
                assert isinstance(metric, str), f"{service} metric {metric} must be a string"

    def test_service_to_metrics_excluded_services_not_present(self):
        """AppFlow, Glue, Batch must NOT be in SERVICE_TO_METRICS."""
        assert 'AppFlow' not in SERVICE_TO_METRICS
        assert 'Glue' not in SERVICE_TO_METRICS
        assert 'Batch' not in SERVICE_TO_METRICS


class TestServiceToResourceType:
    """Test SERVICE_TO_RESOURCE_TYPE constant."""

    def test_service_to_resource_type_has_all_12_services(self):
        """SERVICE_TO_RESOURCE_TYPE must have entries for all 12 services."""
        assert len(SERVICE_TO_RESOURCE_TYPE) == 12

    def test_service_to_resource_type_contains_all_required_services(self):
        """Verify all 12 required services have resource type mappings."""
        required_services = {
            'EC2', 'RDS', 'Lambda', 'S3', 'DynamoDB', 'CloudFront',
            'ElasticSearch', 'Kinesis', 'SNS', 'SQS', 'ECS', 'EKS'
        }
        assert set(SERVICE_TO_RESOURCE_TYPE.keys()) == required_services

    def test_service_to_resource_type_uses_correct_strings(self):
        """Verify ResourceType strings match CloudTrail convention (AWS::Service::Resource)."""
        expected = {
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
        assert SERVICE_TO_RESOURCE_TYPE == expected

    def test_service_to_resource_type_excluded_services_not_present(self):
        """AppFlow, Glue, Batch must NOT be in SERVICE_TO_RESOURCE_TYPE."""
        assert 'AppFlow' not in SERVICE_TO_RESOURCE_TYPE
        assert 'Glue' not in SERVICE_TO_RESOURCE_TYPE
        assert 'Batch' not in SERVICE_TO_RESOURCE_TYPE


class TestCauseDetectionThresholds:
    """Test CAUSE_DETECTION_THRESHOLDS constant."""

    def test_cause_detection_thresholds_has_required_keys(self):
        """CAUSE_DETECTION_THRESHOLDS must have 3 required keys."""
        required_keys = {
            'MIN_INSTANCE_LAUNCH_COUNT',
            'MIN_TOTAL_EVENTS',
            'MIN_NETWORK_SPIKE_MBPS'
        }
        assert set(CAUSE_DETECTION_THRESHOLDS.keys()) == required_keys

    def test_cause_detection_thresholds_correct_values(self):
        """Verify threshold values match architecture specification."""
        assert CAUSE_DETECTION_THRESHOLDS['MIN_INSTANCE_LAUNCH_COUNT'] == 10
        assert CAUSE_DETECTION_THRESHOLDS['MIN_TOTAL_EVENTS'] == 20
        assert CAUSE_DETECTION_THRESHOLDS['MIN_NETWORK_SPIKE_MBPS'] == 50

    def test_cause_detection_thresholds_all_values_are_integers(self):
        """All threshold values must be integers."""
        for key, value in CAUSE_DETECTION_THRESHOLDS.items():
            assert isinstance(value, int), f"{key} must be an integer, got {type(value)}"


class TestKnownServices:
    """Test KNOWN_SERVICES constant."""

    def test_known_services_is_a_set(self):
        """KNOWN_SERVICES must be a Set[str]."""
        assert isinstance(KNOWN_SERVICES, set)

    def test_known_services_has_all_12_services(self):
        """KNOWN_SERVICES must contain exactly 12 services."""
        assert len(KNOWN_SERVICES) == 12

    def test_known_services_matches_service_to_namespace_keys(self):
        """KNOWN_SERVICES must be derived from SERVICE_TO_NAMESPACE keys."""
        assert KNOWN_SERVICES == set(SERVICE_TO_NAMESPACE.keys())

    def test_known_services_contains_all_required_services(self):
        """Verify all 12 required services are in KNOWN_SERVICES."""
        required_services = {
            'EC2', 'RDS', 'Lambda', 'S3', 'DynamoDB', 'CloudFront',
            'ElasticSearch', 'Kinesis', 'SNS', 'SQS', 'ECS', 'EKS'
        }
        assert KNOWN_SERVICES == required_services


# ============================================================================
# Tests for Constants Consistency
# ============================================================================

class TestConstantsConsistency:
    """Test invariants across all constants."""

    def test_constants_consistency_all_services_in_namespace_have_metrics(self):
        """SERVICE_TO_METRICS must have entries for all services in SERVICE_TO_NAMESPACE."""
        for service in SERVICE_TO_NAMESPACE.keys():
            assert service in SERVICE_TO_METRICS, (
                f"Service '{service}' in SERVICE_TO_NAMESPACE but not in "
                f"SERVICE_TO_METRICS"
            )

    def test_constants_consistency_all_services_in_namespace_have_resource_type(self):
        """SERVICE_TO_RESOURCE_TYPE must have entries for all services in SERVICE_TO_NAMESPACE."""
        for service in SERVICE_TO_NAMESPACE.keys():
            assert service in SERVICE_TO_RESOURCE_TYPE, (
                f"Service '{service}' in SERVICE_TO_NAMESPACE but not in "
                f"SERVICE_TO_RESOURCE_TYPE"
            )

    def test_constants_consistency_no_extra_services_in_metrics(self):
        """SERVICE_TO_METRICS must not have services not in SERVICE_TO_NAMESPACE."""
        for service in SERVICE_TO_METRICS.keys():
            assert service in SERVICE_TO_NAMESPACE, (
                f"Service '{service}' in SERVICE_TO_METRICS but not in "
                f"SERVICE_TO_NAMESPACE"
            )

    def test_constants_consistency_no_extra_services_in_resource_type(self):
        """SERVICE_TO_RESOURCE_TYPE must not have services not in SERVICE_TO_NAMESPACE."""
        for service in SERVICE_TO_RESOURCE_TYPE.keys():
            assert service in SERVICE_TO_NAMESPACE, (
                f"Service '{service}' in SERVICE_TO_RESOURCE_TYPE but not in "
                f"SERVICE_TO_NAMESPACE"
            )

    def test_constants_consistency_all_mappings_equal_size(self):
        """All three service mappings must have the same number of entries."""
        assert len(SERVICE_TO_NAMESPACE) == len(SERVICE_TO_METRICS)
        assert len(SERVICE_TO_NAMESPACE) == len(SERVICE_TO_RESOURCE_TYPE)


# ============================================================================
# Tests for Excluded Services
# ============================================================================

class TestExcludedServices:
    """Test that deprecated services are completely removed."""

    def test_excluded_services_appflow_not_in_any_mapping(self):
        """AppFlow must be excluded from all three mappings."""
        assert 'AppFlow' not in SERVICE_TO_NAMESPACE
        assert 'AppFlow' not in SERVICE_TO_METRICS
        assert 'AppFlow' not in SERVICE_TO_RESOURCE_TYPE
        assert 'AppFlow' not in KNOWN_SERVICES

    def test_excluded_services_glue_not_in_any_mapping(self):
        """Glue must be excluded from all three mappings."""
        assert 'Glue' not in SERVICE_TO_NAMESPACE
        assert 'Glue' not in SERVICE_TO_METRICS
        assert 'Glue' not in SERVICE_TO_RESOURCE_TYPE
        assert 'Glue' not in KNOWN_SERVICES

    def test_excluded_services_batch_not_in_any_mapping(self):
        """Batch must be excluded from all three mappings."""
        assert 'Batch' not in SERVICE_TO_NAMESPACE
        assert 'Batch' not in SERVICE_TO_METRICS
        assert 'Batch' not in SERVICE_TO_RESOURCE_TYPE
        assert 'Batch' not in KNOWN_SERVICES
