"""
Tests for cost-anomaly-investigate investigate.py module.

Tests cover:
- Module-level constants consistency (SERVICE_TO_NAMESPACE, SERVICE_TO_METRICS, SERVICE_TO_RESOURCE_TYPE)
- CAUSE_DETECTION_THRESHOLDS presence
- KNOWN_SERVICES correctness
- Service invariants (no missing keys, excluded services not present)
"""

import pytest
import sys
import os
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

# Import the constants under test
SERVICE_TO_NAMESPACE = investigate_module.SERVICE_TO_NAMESPACE
SERVICE_TO_METRICS = investigate_module.SERVICE_TO_METRICS
SERVICE_TO_RESOURCE_TYPE = investigate_module.SERVICE_TO_RESOURCE_TYPE
CAUSE_DETECTION_THRESHOLDS = investigate_module.CAUSE_DETECTION_THRESHOLDS
KNOWN_SERVICES = investigate_module.KNOWN_SERVICES


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

    def test_service_to_namespace_all_values_non_empty(self):
        """All namespace values must be non-empty strings."""
        for service, namespace in SERVICE_TO_NAMESPACE.items():
            assert isinstance(namespace, str)
            assert len(namespace) > 0


class TestServiceToMetrics:
    """Test SERVICE_TO_METRICS constant."""

    def test_service_to_metrics_has_all_12_services(self):
        """SERVICE_TO_METRICS must contain all 12 services."""
        assert len(SERVICE_TO_METRICS) == 12

    def test_service_to_metrics_contains_all_required_services(self):
        """All 12 services from SERVICE_TO_NAMESPACE must exist in SERVICE_TO_METRICS."""
        assert set(SERVICE_TO_METRICS.keys()) == set(SERVICE_TO_NAMESPACE.keys())

    def test_service_to_metrics_all_have_non_empty_lists(self):
        """Every service must have at least one metric."""
        for service, metrics in SERVICE_TO_METRICS.items():
            assert isinstance(metrics, list)
            assert len(metrics) > 0
            # Verify all metrics are non-empty strings
            for metric in metrics:
                assert isinstance(metric, str)
                assert len(metric) > 0

    def test_service_to_metrics_excluded_services_not_present(self):
        """AppFlow, Glue, Batch must NOT be in SERVICE_TO_METRICS."""
        assert 'AppFlow' not in SERVICE_TO_METRICS
        assert 'Glue' not in SERVICE_TO_METRICS
        assert 'Batch' not in SERVICE_TO_METRICS


class TestServiceToResourceType:
    """Test SERVICE_TO_RESOURCE_TYPE constant."""

    def test_service_to_resource_type_has_all_12_services(self):
        """SERVICE_TO_RESOURCE_TYPE must contain all 12 services."""
        assert len(SERVICE_TO_RESOURCE_TYPE) == 12

    def test_service_to_resource_type_contains_all_required_services(self):
        """All 12 services from SERVICE_TO_NAMESPACE must exist in SERVICE_TO_RESOURCE_TYPE."""
        assert set(SERVICE_TO_RESOURCE_TYPE.keys()) == set(SERVICE_TO_NAMESPACE.keys())

    def test_service_to_resource_type_uses_correct_strings(self):
        """Verify CloudTrail ResourceType strings match architecture exactly."""
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

    def test_service_to_resource_type_all_values_non_empty(self):
        """All ResourceType values must be non-empty strings."""
        for service, resource_type in SERVICE_TO_RESOURCE_TYPE.items():
            assert isinstance(resource_type, str)
            assert len(resource_type) > 0


class TestCauseDetectionThresholds:
    """Test CAUSE_DETECTION_THRESHOLDS constant."""

    def test_cause_detection_thresholds_has_required_keys(self):
        """CAUSE_DETECTION_THRESHOLDS must contain at least the 3 required keys."""
        required_keys = {
            'MIN_INSTANCE_LAUNCH_COUNT',
            'MIN_TOTAL_EVENTS',
            'MIN_NETWORK_SPIKE_MBPS'
        }
        assert required_keys.issubset(set(CAUSE_DETECTION_THRESHOLDS.keys()))

    def test_cause_detection_thresholds_values_are_positive_integers(self):
        """All threshold values must be positive integers."""
        for threshold_name, threshold_value in CAUSE_DETECTION_THRESHOLDS.items():
            assert isinstance(threshold_value, int)
            assert threshold_value > 0

    def test_cause_detection_thresholds_required_values(self):
        """Verify the three required thresholds have expected values."""
        assert CAUSE_DETECTION_THRESHOLDS['MIN_INSTANCE_LAUNCH_COUNT'] == 10
        assert CAUSE_DETECTION_THRESHOLDS['MIN_TOTAL_EVENTS'] == 20
        assert CAUSE_DETECTION_THRESHOLDS['MIN_NETWORK_SPIKE_MBPS'] == 50


class TestKnownServices:
    """Test KNOWN_SERVICES constant."""

    def test_known_services_is_set(self):
        """KNOWN_SERVICES must be a set."""
        assert isinstance(KNOWN_SERVICES, set)

    def test_known_services_equals_service_to_namespace_keys(self):
        """KNOWN_SERVICES must equal set(SERVICE_TO_NAMESPACE.keys())."""
        expected = set(SERVICE_TO_NAMESPACE.keys())
        assert KNOWN_SERVICES == expected

    def test_known_services_has_12_services(self):
        """KNOWN_SERVICES must contain exactly 12 services."""
        assert len(KNOWN_SERVICES) == 12

    def test_known_services_contains_all_required_services(self):
        """KNOWN_SERVICES must contain all 12 required services."""
        required_services = {
            'EC2', 'RDS', 'Lambda', 'S3', 'DynamoDB', 'CloudFront',
            'ElasticSearch', 'Kinesis', 'SNS', 'SQS', 'ECS', 'EKS'
        }
        assert KNOWN_SERVICES == required_services

    def test_known_services_excluded_services_not_present(self):
        """AppFlow, Glue, Batch must NOT be in KNOWN_SERVICES."""
        assert 'AppFlow' not in KNOWN_SERVICES
        assert 'Glue' not in KNOWN_SERVICES
        assert 'Batch' not in KNOWN_SERVICES


# ============================================================================
# Integration Tests for Constants Consistency
# ============================================================================

class TestConstantsConsistency:
    """Test invariants across all service mappings."""

    def test_constants_consistency_all_services_in_all_mappings(self):
        """
        CRITICAL INVARIANT: Every key in SERVICE_TO_NAMESPACE must exist
        in both SERVICE_TO_METRICS and SERVICE_TO_RESOURCE_TYPE.

        This prevents KeyError at runtime during cause detection and
        metric/event retrieval.
        """
        for service in SERVICE_TO_NAMESPACE.keys():
            assert service in SERVICE_TO_METRICS, (
                f"Service '{service}' in SERVICE_TO_NAMESPACE but missing "
                f"from SERVICE_TO_METRICS"
            )
            assert service in SERVICE_TO_RESOURCE_TYPE, (
                f"Service '{service}' in SERVICE_TO_NAMESPACE but missing "
                f"from SERVICE_TO_RESOURCE_TYPE"
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
