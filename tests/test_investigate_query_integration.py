"""
Integration tests for cost-anomaly-investigate and cost-explorer-query interaction.

Tests verify that the investigate.py skill correctly integrates with Phase 1's query.py
CostExplorerClient for spike detection. Focus areas:
1. Correct import of CostExplorerClient from query.py
2. Correct date range calculation for baseline (previous month) and spike date
3. Correct service name filtering in detect_spike() method
4. Error propagation from query.py failures
"""

import pytest
import sys
import os
import importlib.util
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Load the investigate module
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


class TestDetectSpikeWithPhase1Integration:
    """Test integration between detect_spike() and query.py CostExplorerClient."""

    def test_detect_spike_imports_query_module(self):
        """Test detect_spike correctly imports CostExplorerClient from query.py."""
        mock_ce = Mock()
        mock_ce.get_costs.return_value = [('EC2', 1000.0)]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module) as mock_import:
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            investigator.detect_spike()

            # Verify importlib was called with correct module name
            mock_import.assert_called_once()
            call_args = mock_import.call_args[0]
            assert 'cost-explorer-query' in call_args[0]
            assert 'query' in call_args[0]

    def test_detect_spike_calls_query_twice(self):
        """Test detect_spike calls CostExplorerClient.get_costs() twice: baseline and spike."""
        mock_ce = Mock()
        # First call: previous month costs, Second call: spike date costs
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0), ('RDS', 10000.0)],
            [('EC2', 5000.0), ('RDS', 2000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            investigator.detect_spike()

            # Verify get_costs was called twice
            assert mock_ce.get_costs.call_count == 2

    def test_detect_spike_baseline_call_previous_month(self):
        """Test first get_costs() call queries the previous calendar month."""
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0)],
            [('EC2', 5000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            investigator.detect_spike()

            # Check first call (baseline) arguments
            first_call = mock_ce.get_costs.call_args_list[0]
            start_date_arg = first_call.kwargs['start_date']
            end_date_arg = first_call.kwargs['end_date']

            # For 2024-03-15, previous month is Feb 2024
            assert start_date_arg == '2024-02-01'
            assert end_date_arg == '2024-03-01'  # Exclusive end boundary
            assert first_call.kwargs['group_by'] == 'service'

    def test_detect_spike_spike_call_single_day(self):
        """Test second get_costs() call queries the spike date (single day)."""
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0)],
            [('EC2', 5000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            investigator.detect_spike()

            # Check second call (spike date) arguments
            second_call = mock_ce.get_costs.call_args_list[1]
            start_date_arg = second_call.kwargs['start_date']
            end_date_arg = second_call.kwargs['end_date']

            # Both should be the same date (single day query)
            assert start_date_arg == '2024-03-15'
            assert end_date_arg == '2024-03-15'
            assert second_call.kwargs['group_by'] == 'service'

    def test_detect_spike_filters_service_from_results(self):
        """Test detect_spike filters results to match the service parameter."""
        mock_ce = Mock()
        # Return multiple services, should filter to EC2 only
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0), ('RDS', 10000.0), ('Lambda', 5000.0)],
            [('EC2', 5000.0), ('RDS', 2000.0), ('Lambda', 500.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result = investigator.detect_spike()

            # Should have EC2 costs, not RDS or Lambda
            assert result.service == 'EC2'
            assert result.baseline_cost == 1000.0  # 29000 / 29 days in Feb 2024
            assert result.spike_cost == 5000.0

    def test_detect_spike_handles_missing_service_in_results(self):
        """Test detect_spike handles case where service is not in results (zero cost)."""
        mock_ce = Mock()
        # Previous month has EC2, spike date doesn't
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0), ('RDS', 10000.0)],
            [('RDS', 2000.0)]  # EC2 missing from spike results
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result = investigator.detect_spike()

            # Should default to 0.0 if service not in spike results
            assert result.spike_cost == 0.0
            assert result.baseline_cost == 1000.0

    def test_detect_spike_calculates_baseline_correctly_feb_leap_year(self):
        """Test baseline calculation accounts for Feb leap year (29 days in 2024)."""
        mock_ce = Mock()
        # Feb 2024 has 29 days, so should divide by 29
        mock_ce.get_costs.side_effect = [
            [('EC2', 2900.0)],  # 100.0 per day
            [('EC2', 150.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result = investigator.detect_spike()

            assert result.baseline_cost == 100.0  # 2900 / 29

    def test_detect_spike_calculates_baseline_correctly_feb_non_leap_year(self):
        """Test baseline calculation accounts for Feb non-leap year (28 days in 2023)."""
        mock_ce = Mock()
        # Feb 2023 has 28 days, so should divide by 28
        mock_ce.get_costs.side_effect = [
            [('EC2', 2800.0)],  # 100.0 per day
            [('EC2', 150.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2023-03-15', 'EC2')
            result = investigator.detect_spike()

            assert result.baseline_cost == 100.0  # 2800 / 28

    def test_detect_spike_propagates_ce_client_errors(self):
        """Test detect_spike propagates exceptions from CostExplorerClient."""
        import botocore.exceptions

        mock_ce = Mock()
        # Simulate ClientError from Cost Explorer API
        mock_ce.get_costs.side_effect = botocore.exceptions.ClientError(
            {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'Access denied'}},
            'GetCostAndUsage'
        )

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')

            # Should propagate the exception
            with pytest.raises(botocore.exceptions.ClientError) as exc_info:
                investigator.detect_spike()

            assert 'UnauthorizedOperation' in str(exc_info.value)

    def test_detect_spike_propagates_no_credentials_error(self):
        """Test detect_spike propagates NoCredentialsError from CostExplorerClient."""
        import botocore.exceptions

        mock_ce = Mock()
        # Simulate NoCredentialsError
        mock_ce.get_costs.side_effect = botocore.exceptions.NoCredentialsError()

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')

            # Should propagate the exception
            with pytest.raises(botocore.exceptions.NoCredentialsError):
                investigator.detect_spike()

    def test_detect_spike_year_boundary_january(self):
        """Test date range calculation for January (previous month is December of prior year)."""
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 31000.0)],  # Dec 2023 has 31 days
            [('EC2', 5000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-01-15', 'EC2')
            result = investigator.detect_spike()

            # Check that previous month is Dec 2023
            first_call = mock_ce.get_costs.call_args_list[0]
            assert first_call.kwargs['start_date'] == '2023-12-01'
            assert first_call.kwargs['end_date'] == '2024-01-01'

            assert result.baseline_cost == 1000.0  # 31000 / 31

    def test_detect_spike_with_rds_service(self):
        """Test detect_spike works correctly for RDS service."""
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 10000.0), ('RDS', 6000.0)],
            [('EC2', 5000.0), ('RDS', 3000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'RDS')
            result = investigator.detect_spike()

            # Should filter to RDS, not EC2
            assert result.service == 'RDS'
            assert abs(result.baseline_cost - 206.897) < 0.01  # 6000 / 29 (approx)
            assert result.spike_cost == 3000.0

    def test_detect_spike_multiple_rds_calls_different_services(self):
        """Test multiple investigations with different services use correct filtering."""
        mock_ce = Mock()

        # Scenario: investigate both EC2 and Lambda
        mock_module = Mock()

        def ce_factory():
            client = Mock()
            client.get_costs.side_effect = [
                [('EC2', 29000.0), ('Lambda', 1000.0), ('RDS', 5000.0)],
                [('EC2', 5000.0), ('Lambda', 200.0), ('RDS', 1000.0)]
            ]
            return client

        mock_module.CostExplorerClient = ce_factory

        with patch('importlib.import_module', return_value=mock_module):
            # First investigation: EC2
            investigator_ec2 = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
            result_ec2 = investigator_ec2.detect_spike()

            assert result_ec2.service == 'EC2'
            assert result_ec2.spike_cost == 5000.0

            # Recreate for second investigation: Lambda
            mock_module.CostExplorerClient = ce_factory
            investigator_lambda = investigate_module.CostAnomalyInvestigator('2024-03-15', 'Lambda')
            result_lambda = investigator_lambda.detect_spike()

            assert result_lambda.service == 'Lambda'
            assert result_lambda.spike_cost == 200.0


class TestInvestigateOrchestrationWithPhase1:
    """Test full investigate() orchestration including Phase 1 integration."""

    def test_investigate_full_flow_with_mocked_phase1(self):
        """Test investigate() calls detect_spike with mocked Phase 1, then CloudWatch/CloudTrail."""
        import botocore.stub

        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [('EC2', 29000.0)],
            [('EC2', 5000.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        # Setup CloudWatch and CloudTrail stubs
        import boto3

        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = botocore.stub.Stubber(cw_client)

        ct_client = boto3.client('cloudtrail', region_name='us-east-1')
        ct_stubber = botocore.stub.Stubber(ct_client)

        # Stub CloudWatch metrics
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

        # Stub CloudTrail events
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

        with patch('importlib.import_module', return_value=mock_module):
            with cw_stubber, ct_stubber:
                investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', 'EC2')
                investigator._cloudwatch = cw_client
                investigator._cloudtrail = ct_client

                report = investigator.investigate()

                # Verify spike was detected via Phase 1
                assert report.spike.date == '2024-03-15'
                assert report.spike.service == 'EC2'
                assert report.spike.baseline_cost == 1000.0  # 29000 / 29
                assert report.spike.spike_cost == 5000.0
                assert report.spike.delta == 4000.0


class TestCostAnomalyInvestigatorMultipleServices:
    """Test investigate() with various services to ensure service constants are correct."""

    @pytest.mark.parametrize("service", [
        "EC2", "RDS", "Lambda", "S3", "DynamoDB",
        "CloudFront", "ElasticSearch", "Kinesis", "SNS", "SQS", "ECS", "EKS"
    ])
    def test_detect_spike_all_supported_services(self, service):
        """Test detect_spike works for all supported services."""
        mock_ce = Mock()
        mock_ce.get_costs.side_effect = [
            [(service, 1000.0)],
            [(service, 500.0)]
        ]

        mock_module = Mock()
        mock_module.CostExplorerClient = Mock(return_value=mock_ce)

        with patch('importlib.import_module', return_value=mock_module):
            investigator = investigate_module.CostAnomalyInvestigator('2024-03-15', service)
            result = investigator.detect_spike()

            assert result.service == service
            assert result.spike_cost == 500.0
