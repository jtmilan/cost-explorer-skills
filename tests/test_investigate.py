"""
Tests for cost-anomaly-investigate investigate.py module.

Tests cover:
- Dataclass instantiation and field access (SpikeSummary, MetricDatapoint, CloudTrailEvent, LikelyCause, InvestigationReport)
- Module-level constants consistency (SERVICE_TO_NAMESPACE, SERVICE_TO_METRICS, SERVICE_TO_RESOURCE_TYPE)
- CAUSE_DETECTION_THRESHOLDS presence
- KNOWN_SERVICES correctness
- Service invariants (no missing keys, excluded services not present)
- Validator functions (validate_date, validate_service, parse_iso_date_to_utc, get_previous_month_range)
"""

import pytest
import sys
import os
import argparse
from datetime import datetime, timezone
from typing import List, Dict
import importlib.util
import boto3


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


# ============================================================================
# Tests for Validator Functions
# ============================================================================

class TestValidateDate:
    """Test validate_date function."""

    def test_validate_date_valid(self):
        """Test validate_date accepts valid dates."""
        # Test various valid dates
        assert investigate_module.validate_date("2024-03-15") == "2024-03-15"
        assert investigate_module.validate_date("2024-01-01") == "2024-01-01"
        assert investigate_module.validate_date("2023-12-31") == "2023-12-31"
        assert investigate_module.validate_date("2000-02-29") == "2000-02-29"  # Leap year

    def test_validate_date_invalid_format_short(self):
        """Test validate_date rejects dates with wrong separator spacing."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-3-15")  # Single digit month

    def test_validate_date_invalid_format_slash(self):
        """Test validate_date rejects non-dash separators."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024/03/15")

    def test_validate_date_invalid_format_no_separator(self):
        """Test validate_date rejects dates without separators."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("20240315")

    def test_validate_date_invalid_month(self):
        """Test validate_date rejects invalid month numbers."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-13-01")

    def test_validate_date_invalid_day(self):
        """Test validate_date rejects invalid day numbers."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-02-30")  # Feb doesn't have 30 days

    def test_validate_date_invalid_leap_year_day(self):
        """Test validate_date rejects invalid day in non-leap year."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2023-02-29")  # 2023 is not a leap year

    def test_validate_date_invalid_day_31_april(self):
        """Test validate_date rejects day 31 for April (30-day month)."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-04-31")

    def test_validate_date_invalid_zero_month(self):
        """Test validate_date rejects month zero."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-00-15")

    def test_validate_date_invalid_zero_day(self):
        """Test validate_date rejects day zero."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_date("2024-03-00")


class TestValidateService:
    """Test validate_service function."""

    def test_validate_service_valid(self):
        """Test validate_service accepts known services."""
        # Test all known services
        assert investigate_module.validate_service("EC2") == "EC2"
        assert investigate_module.validate_service("RDS") == "RDS"
        assert investigate_module.validate_service("Lambda") == "Lambda"
        assert investigate_module.validate_service("S3") == "S3"
        assert investigate_module.validate_service("DynamoDB") == "DynamoDB"
        assert investigate_module.validate_service("CloudFront") == "CloudFront"
        assert investigate_module.validate_service("ElasticSearch") == "ElasticSearch"
        assert investigate_module.validate_service("Kinesis") == "Kinesis"
        assert investigate_module.validate_service("SNS") == "SNS"
        assert investigate_module.validate_service("SQS") == "SQS"
        assert investigate_module.validate_service("ECS") == "ECS"
        assert investigate_module.validate_service("EKS") == "EKS"

    def test_validate_service_unknown(self):
        """Test validate_service rejects unknown services."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            investigate_module.validate_service("UnknownService")
        error_msg = str(exc_info.value)
        assert "UnknownService" in error_msg
        assert "not recognized" in error_msg

    def test_validate_service_unknown_with_valid_services_list(self):
        """Test validate_service error message includes valid services."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            investigate_module.validate_service("InvalidService")
        error_msg = str(exc_info.value)
        # Check that some valid services are mentioned in error
        assert "EC2" in error_msg or "ECS" in error_msg

    def test_validate_service_case_sensitive_lowercase(self):
        """Test validate_service is case-sensitive (rejects lowercase)."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_service("ec2")

    def test_validate_service_case_sensitive_mixed(self):
        """Test validate_service is case-sensitive (rejects mixed case)."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_service("Ec2")

    def test_validate_service_excluded_services(self):
        """Test validate_service rejects excluded services."""
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_service("AppFlow")
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_service("Glue")
        with pytest.raises(argparse.ArgumentTypeError):
            investigate_module.validate_service("Batch")


class TestParseIsoDateToUtc:
    """Test parse_iso_date_to_utc function."""

    def test_parse_iso_date_to_utc_basic(self):
        """Test parse_iso_date_to_utc returns correct start and end times."""
        start, end = investigate_module.parse_iso_date_to_utc("2024-03-15")

        assert start == datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc)

    def test_parse_iso_date_to_utc_timezone_aware(self):
        """Test parse_iso_date_to_utc returns timezone-aware datetimes."""
        start, end = investigate_module.parse_iso_date_to_utc("2024-03-15")

        # Check that both have UTC timezone
        assert start.tzinfo is not None
        assert start.tzinfo == timezone.utc
        assert end.tzinfo is not None
        assert end.tzinfo == timezone.utc

    def test_parse_iso_date_to_utc_first_day_of_month(self):
        """Test parse_iso_date_to_utc with first day of month."""
        start, end = investigate_module.parse_iso_date_to_utc("2024-01-01")

        assert start == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 1, 1, 23, 59, 59, tzinfo=timezone.utc)

    def test_parse_iso_date_to_utc_last_day_of_month(self):
        """Test parse_iso_date_to_utc with last day of month."""
        start, end = investigate_module.parse_iso_date_to_utc("2024-12-31")

        assert start == datetime(2024, 12, 31, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_parse_iso_date_to_utc_leap_year(self):
        """Test parse_iso_date_to_utc with leap year date."""
        start, end = investigate_module.parse_iso_date_to_utc("2024-02-29")

        assert start == datetime(2024, 2, 29, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 2, 29, 23, 59, 59, tzinfo=timezone.utc)

    def test_parse_iso_date_to_utc_returns_tuple(self):
        """Test parse_iso_date_to_utc returns a tuple."""
        result = investigate_module.parse_iso_date_to_utc("2024-03-15")

        assert isinstance(result, tuple)
        assert len(result) == 2


class TestGetPreviousMonthRange:
    """Test get_previous_month_range function."""

    def test_get_previous_month_range_mid_month(self):
        """Test get_previous_month_range for mid-month date."""
        start, end = investigate_module.get_previous_month_range("2024-03-15")

        assert start == datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_year_boundary(self):
        """Test get_previous_month_range handles year boundary (Jan -> Dec prev year)."""
        start, end = investigate_module.get_previous_month_range("2024-01-15")

        assert start == datetime(2023, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_leap_year(self):
        """Test get_previous_month_range with leap year."""
        start, end = investigate_module.get_previous_month_range("2024-03-15")

        # Feb 2024 is a leap year with 29 days, so previous month starts Feb 1
        assert start == datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_february_non_leap(self):
        """Test get_previous_month_range with March of non-leap year."""
        start, end = investigate_module.get_previous_month_range("2023-03-15")

        # Feb 2023 is not a leap year with 28 days, so previous month starts Feb 1
        assert start == datetime(2023, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2023, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_first_day_of_month(self):
        """Test get_previous_month_range with first day of month."""
        start, end = investigate_module.get_previous_month_range("2024-03-01")

        assert start == datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_last_day_of_month(self):
        """Test get_previous_month_range with last day of month."""
        start, end = investigate_module.get_previous_month_range("2024-03-31")

        assert start == datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_get_previous_month_range_timezone_aware(self):
        """Test get_previous_month_range returns timezone-aware datetimes."""
        start, end = investigate_module.get_previous_month_range("2024-03-15")

        assert start.tzinfo is not None
        assert start.tzinfo == timezone.utc
        assert end.tzinfo is not None
        assert end.tzinfo == timezone.utc

    def test_get_previous_month_range_december_to_november(self):
        """Test get_previous_month_range for December."""
        start, end = investigate_module.get_previous_month_range("2024-12-15")

        assert start == datetime(2024, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert end == datetime(2024, 12, 1, 0, 0, 0, tzinfo=timezone.utc)


# ============================================================================
# Tests for CostAnomalyInvestigator Class
# ============================================================================

class TestCostAnomalyInvestigatorDetectSpike:
    """Test CostAnomalyInvestigator.detect_spike() method."""

    def test_detect_spike_with_baseline(self):
        """Test detect_spike with previous month data (baseline available)."""
        from unittest.mock import Mock, patch

        # Create a mock module with CostExplorerClient
        mock_ce = Mock()
        # Use consistent values: Feb 2024 has 29 days, so 29000 / 29 = 1000
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0), ('RDS', 10000.0)],  # Previous month (29 days in Feb 2024)
            [('EC2', 5000.0), ('RDS', 2000.0)]     # Spike date
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        # Patch importlib.import_module to return our mock module
        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result = investigator.detect_spike()

            # Verify result
            assert isinstance(result, investigate_module.SpikeSummary)
            assert result.date == '2024-03-15'
            assert result.service == 'EC2'
            assert result.baseline_cost == 1000.0  # 29000 / 29 days
            assert result.spike_cost == 5000.0
            assert result.delta == 4000.0
            assert result.delta_percent == 400.0  # 4000 / 1000 * 100

    def test_detect_spike_zero_baseline(self):
        """Test detect_spike with zero baseline (previous month unavailable)."""
        from unittest.mock import Mock, patch

        # Create a mock module with CostExplorerClient
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('RDS', 10000.0)],              # Previous month (no EC2)
            [('EC2', 5000.0), ('RDS', 2000.0)]  # Spike date
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result = investigator.detect_spike()

            # Verify result
            assert result.baseline_cost == 0.0
            assert result.spike_cost == 5000.0
            assert result.delta == 5000.0
            assert result.delta_percent == 0.0  # Undefined ratio when baseline=0


class TestCostAnomalyInvestigatorCloudWatchMetrics:
    """Test CostAnomalyInvestigator.get_cloudwatch_metrics() method."""

    def test_get_cloudwatch_metrics_retrieval(self):
        """Test get_cloudwatch_metrics fetches and returns metrics."""
        from unittest.mock import Mock, patch
        from botocore.stub import Stubber

        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')

        # Create stubbed CloudWatch client
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        stubber = Stubber(cw_client)

        # Mock response for CPUUtilization
        stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {
                        'Timestamp': datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
                        'Average': 45.2,
                        'Unit': 'Percent'
                    },
                    {
                        'Timestamp': datetime(2024, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
                        'Average': 55.5,
                        'Unit': 'Percent'
                    }
                ]
            },
            expected_params={
                'Namespace': 'AWS/EC2',
                'MetricName': 'CPUUtilization',
                'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                'Period': 60,
                'Statistics': ['Average', 'Sum', 'Maximum']
            }
        )

        # Mock response for NetworkIn (empty)
        stubber.add_response(
            'get_metric_statistics',
            {'Datapoints': []},
            expected_params={
                'Namespace': 'AWS/EC2',
                'MetricName': 'NetworkIn',
                'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                'Period': 60,
                'Statistics': ['Average', 'Sum', 'Maximum']
            }
        )

        # Mock response for NetworkOut (empty)
        stubber.add_response(
            'get_metric_statistics',
            {'Datapoints': []},
            expected_params={
                'Namespace': 'AWS/EC2',
                'MetricName': 'NetworkOut',
                'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                'Period': 60,
                'Statistics': ['Average', 'Sum', 'Maximum']
            }
        )

        with stubber:
            investigator._cloudwatch = cw_client
            result = investigator.get_cloudwatch_metrics()

        # Verify result
        assert isinstance(result, dict)
        assert 'CPUUtilization' in result
        assert len(result['CPUUtilization']) == 2
        assert result['CPUUtilization'][0].value == 45.2
        assert result['CPUUtilization'][0].unit == 'Percent'
        assert result['CPUUtilization'][0].statistic == 'Average'
        # NetworkIn and NetworkOut should be omitted (empty)
        assert 'NetworkIn' not in result
        assert 'NetworkOut' not in result


class TestCostAnomalyInvestigatorCloudTrailEvents:
    """Test CostAnomalyInvestigator.get_cloudtrail_events() method."""

    def test_cloudtrail_event_filtering(self):
        """Test get_cloudtrail_events filters to mutating verbs only."""
        from botocore.stub import Stubber

        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')

        # Create stubbed CloudTrail client
        ct_client = boto3.client('cloudtrail', region_name='us-east-1')
        stubber = Stubber(ct_client)

        # Mock response with mixed mutating and read-only events
        # Note: CloudTrail API uses different field names than our CloudTrailEvent dataclass
        stubber.add_response(
            'lookup_events',
            {
                'Events': [
                    {
                        'EventTime': datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc),
                        'Username': 'arn:aws:iam::123456789012:user/alice',
                        'EventName': 'CreateInstance',  # Mutating, matches Create.*
                        'Resources': [
                            {'ResourceName': 'i-1234567890abcdef0', 'ResourceType': 'AWS::EC2::Instance'}
                        ]
                    },
                    {
                        'EventTime': datetime(2024, 3, 15, 10, 45, 20, tzinfo=timezone.utc),
                        'Username': 'arn:aws:iam::123456789012:role/lambda-role',
                        'EventName': 'DescribeInstances',  # Read-only, should be filtered out
                        'Resources': []
                    },
                    {
                        'EventTime': datetime(2024, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
                        'Username': 'arn:aws:iam::123456789012:user/bob',
                        'EventName': 'ModifyInstanceAttribute',  # Mutating, matches Modify.*
                        'Resources': [
                            {'ResourceName': 'i-0987654321fedcba0', 'ResourceType': 'AWS::EC2::Instance'}
                        ]
                    }
                ]
            },
            expected_params={
                'LookupAttributes': [
                    {
                        'AttributeKey': 'ResourceType',
                        'AttributeValue': 'AWS::EC2::Instance'
                    }
                ],
                'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                'MaxResults': 50
            }
        )

        with stubber:
            investigator._cloudtrail = ct_client
            result = investigator.get_cloudtrail_events()

        # Verify result
        assert isinstance(result, list)
        assert len(result) == 2  # Only 2 mutating events, DescribeInstances filtered out
        assert result[0].action == 'CreateInstance'
        assert result[1].action == 'ModifyInstanceAttribute'
        # Verify resource names are captured (from ResourceName field)
        assert len(result[0].resource) > 0
        # Verify sorted by timestamp
        assert result[0].timestamp < result[1].timestamp


class TestCostAnomalyInvestigatorDeriveCauses:
    """Test CostAnomalyInvestigator._derive_causes() method."""

    def test_derive_causes_instance_launch_surge(self):
        """Test _derive_causes detects EC2 instance launch surge."""
        spike = investigate_module.SpikeSummary(
            date='2024-03-15',
            service='EC2',
            baseline_cost=1000.0,
            spike_cost=5000.0,
            delta=4000.0,
            delta_percent=400.0
        )

        # Create 15 RunInstances events
        events = [
            investigate_module.CloudTrailEvent(
                timestamp=datetime(2024, 3, 15, 10, i, 0, tzinfo=timezone.utc),
                principal='arn:aws:iam::123456789012:user/alice',
                action='RunInstances',
                resource=[f'arn:aws:ec2:us-east-1:123456789012:instance/i-{i:016d}'],
                source_ip='192.0.2.1'
            )
            for i in range(15)
        ]

        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
        causes = investigator._derive_causes(spike, {}, events)

        # Verify
        assert len(causes) >= 1
        assert causes[0].title == "EC2 instance launch surge"
        assert '15' in causes[0].description

    def test_derive_causes_high_mutation_rate(self):
        """Test _derive_causes detects high mutation rate."""
        spike = investigate_module.SpikeSummary(
            date='2024-03-15',
            service='EC2',
            baseline_cost=1000.0,
            spike_cost=3000.0,
            delta=2000.0,
            delta_percent=200.0
        )

        # Create 25 mutating events (below launch surge threshold but above high mutation threshold)
        events = [
            investigate_module.CloudTrailEvent(
                timestamp=datetime(2024, 3, 15, 10, i % 60, 0, tzinfo=timezone.utc),
                principal='arn:aws:iam::123456789012:user/alice',
                action='ModifyInstanceAttribute' if i % 2 == 0 else 'CreateSecurityGroup',
                resource=['arn:aws:ec2:us-east-1:123456789012:instance/i-123'],
                source_ip='192.0.2.1'
            )
            for i in range(25)
        ]

        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
        causes = investigator._derive_causes(spike, {}, events)

        # Verify
        assert len(causes) >= 1
        assert any('mutating events' in c.description for c in causes)

    def test_derive_causes_fallback(self):
        """Test _derive_causes returns fallback when no rules match."""
        spike = investigate_module.SpikeSummary(
            date='2024-03-15',
            service='EC2',
            baseline_cost=1000.0,
            spike_cost=1100.0,
            delta=100.0,
            delta_percent=10.0
        )

        # No events, no metrics
        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
        causes = investigator._derive_causes(spike, {}, [])

        # Verify fallback is always present
        assert len(causes) >= 1
        assert causes[0].title == "Unable to determine root cause"

    def test_derive_causes_returns_1_to_3_causes(self):
        """Test _derive_causes always returns 1-3 causes (never empty)."""
        spike = investigate_module.SpikeSummary(
            date='2024-03-15',
            service='EC2',
            baseline_cost=1000.0,
            spike_cost=2000.0,
            delta=1000.0,
            delta_percent=100.0
        )

        investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')

        # Test with various event counts
        for event_count in [0, 1, 5, 10, 25, 50]:
            events = [
                investigate_module.CloudTrailEvent(
                    timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
                    principal='arn:aws:iam::123456789012:user/alice',
                    action='RunInstances',
                    resource=['arn:aws:ec2:us-east-1:123456789012:instance/i-123'],
                    source_ip='192.0.2.1'
                )
                for _ in range(event_count)
            ]

            causes = investigator._derive_causes(spike, {}, events)

            # Never empty, max 3
            assert 1 <= len(causes) <= 3
            # All ranks are 1-3
            for i, cause in enumerate(causes, start=1):
                assert cause.rank == i


class TestCostAnomalyInvestigatorOrchestration:
    """Test CostAnomalyInvestigator.investigate() orchestration method."""

    def test_investigate_orchestration(self):
        """Test investigate() calls all methods and returns InvestigationReport."""
        from unittest.mock import Mock, patch
        from botocore.stub import Stubber

        # Create a mock module with CostExplorerClient
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 30000.0)],
            [('EC2', 5000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            # Mock CloudWatch
            cw_client = boto3.client('cloudwatch', region_name='us-east-1')
            cw_stubber = Stubber(cw_client)

            # Mock CloudTrail
            ct_client = boto3.client('cloudtrail', region_name='us-east-1')
            ct_stubber = Stubber(ct_client)

            # Setup CloudWatch stubs for 3 metrics
            for metric_name in ['CPUUtilization', 'NetworkIn', 'NetworkOut']:
                cw_stubber.add_response(
                    'get_metric_statistics',
                    {'Datapoints': []},
                    expected_params={
                        'Namespace': 'AWS/EC2',
                        'MetricName': metric_name,
                        'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                        'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                        'Period': 60,
                        'Statistics': ['Average', 'Sum', 'Maximum']
                    }
                )

            # Setup CloudTrail stub
            ct_stubber.add_response(
                'lookup_events',
                {'Events': []},
                expected_params={
                    'LookupAttributes': [
                        {
                            'AttributeKey': 'ResourceType',
                            'AttributeValue': 'AWS::EC2::Instance'
                        }
                    ],
                    'StartTime': datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc),
                    'EndTime': datetime(2024, 3, 15, 23, 59, 59, tzinfo=timezone.utc),
                    'MaxResults': 50
                }
            )

            with cw_stubber, ct_stubber:
                investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
                investigator._cloudwatch = cw_client
                investigator._cloudtrail = ct_client

                result = investigator.investigate()

                # Verify result
                assert isinstance(result, investigate_module.InvestigationReport)
                assert isinstance(result.spike, investigate_module.SpikeSummary)
                assert isinstance(result.metrics, dict)
                assert isinstance(result.events, list)
                assert isinstance(result.likely_causes, list)
                assert isinstance(result.investigation_date, datetime)
                # Must have 1-3 causes
                assert 1 <= len(result.likely_causes) <= 3
                # Spike data should be set
                assert result.spike.date == '2024-03-15'
                assert result.spike.service == 'EC2'
