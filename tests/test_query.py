"""
Tests for cost-explorer-query query.py module.

Uses botocore.stub.Stubber for AWS API mocking (no live AWS calls).
Tests cover:
- CostExplorerClient pagination and response parsing
- FixtureProvider deterministic fixture data
- OutputFormatter sorting and currency formatting
- main() entry point with --dry-run and normal flow
- Error handling for NoCredentialsError and UnauthorizedOperation
"""

import pytest
from unittest.mock import patch, MagicMock
from botocore.stub import Stubber
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import sys
import os
from io import StringIO
import argparse
import importlib.util

# Load the module directly from file
query_module_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'skills',
    'cost_explorer_query',
    'query.py'
)

# Handle both possible naming conventions
if not os.path.exists(query_module_path):
    query_module_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'skills',
        'cost-explorer-query',
        'query.py'
    )

spec = importlib.util.spec_from_file_location("query", query_module_path)
query_module = importlib.util.module_from_spec(spec)
sys.modules['query'] = query_module
spec.loader.exec_module(query_module)

# Import the module under test
CostExplorerClient = query_module.CostExplorerClient
FixtureProvider = query_module.FixtureProvider
OutputFormatter = query_module.OutputFormatter
main = query_module.main
validate_date = query_module.validate_date
validate_group_by = query_module.validate_group_by


# ============================================================================
# Tests for validate_date function
# ============================================================================

class TestValidateDate:
    """Test date validation function."""

    def test_valid_date(self):
        """Test that valid YYYY-MM-DD format is accepted."""
        assert validate_date('2024-01-01') == '2024-01-01'
        assert validate_date('2024-12-31') == '2024-12-31'

    def test_invalid_date_format_missing_dashes(self):
        """Test that date without dashes is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('20240101')

    def test_invalid_date_format_wrong_order(self):
        """Test that wrong date format is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('01-01-2024')

    def test_invalid_date_format_text(self):
        """Test that text dates are rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('2024-Jan-01')


# ============================================================================
# Tests for validate_group_by function
# ============================================================================

class TestValidateGroupBy:
    """Test group-by validation function."""

    def test_valid_service(self):
        """Test that 'service' is valid."""
        assert validate_group_by('service') == 'service'

    def test_valid_account(self):
        """Test that 'account' is valid."""
        assert validate_group_by('account') == 'account'

    def test_valid_linked_account(self):
        """Test that 'linked-account' is valid."""
        assert validate_group_by('linked-account') == 'linked-account'

    def test_valid_tag(self):
        """Test that 'tag:<name>' format is valid."""
        assert validate_group_by('tag:Environment') == 'tag:Environment'
        assert validate_group_by('tag:Application') == 'tag:Application'

    def test_invalid_group_by(self):
        """Test that invalid group-by values are rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_group_by('invalid')

    def test_invalid_tag_without_colon(self):
        """Test that 'tag' without key is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_group_by('tag')


# ============================================================================
# Tests for CostExplorerClient
# ============================================================================

class TestCostExplorerClient:
    """Test CostExplorerClient class."""

    def test_parse_group_by_service(self):
        """Test _parse_group_by for service dimension."""
        client = CostExplorerClient()
        result = client._parse_group_by('service')
        assert result == [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]

    def test_parse_group_by_account(self):
        """Test _parse_group_by for account dimension."""
        client = CostExplorerClient()
        result = client._parse_group_by('account')
        assert result == [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]

    def test_parse_group_by_linked_account(self):
        """Test _parse_group_by for linked-account dimension."""
        client = CostExplorerClient()
        result = client._parse_group_by('linked-account')
        assert result == [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]

    def test_parse_group_by_tag(self):
        """Test _parse_group_by for tag dimension."""
        client = CostExplorerClient()
        result = client._parse_group_by('tag:Environment')
        assert result == [{'Type': 'TAG', 'Key': 'Environment'}]

    def test_translate_service_name_ec2(self):
        """Test service name translation for EC2."""
        client = CostExplorerClient()
        assert client._translate_service_name('AmazonEC2') == 'EC2'

    def test_translate_service_name_rds(self):
        """Test service name translation for RDS."""
        client = CostExplorerClient()
        assert client._translate_service_name('AmazonRDS') == 'RDS'

    def test_translate_service_name_lambda(self):
        """Test service name translation for Lambda."""
        client = CostExplorerClient()
        assert client._translate_service_name('AWSLambda') == 'Lambda'

    def test_translate_service_name_s3(self):
        """Test service name translation for S3."""
        client = CostExplorerClient()
        assert client._translate_service_name('AmazonSimpleStorageService') == 'S3'

    def test_translate_service_name_unknown(self):
        """Test that unknown service names are returned as-is."""
        client = CostExplorerClient()
        assert client._translate_service_name('UnknownService') == 'UnknownService'

    def test_parse_response_with_service_grouping(self):
        """Test _parse_response for service grouping."""
        client = CostExplorerClient()
        response = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                    'Groups': [
                        {
                            'Keys': ['AmazonEC2'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '1234.56', 'Unit': 'USD'}
                            }
                        },
                        {
                            'Keys': ['AmazonRDS'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '567.89', 'Unit': 'USD'}
                            }
                        }
                    ]
                }
            ]
        }
        results = client._parse_response(response, 'service')
        assert len(results) == 2
        assert ('EC2', 1234.56) in results
        assert ('RDS', 567.89) in results

    def test_parse_response_aggregation_across_time_periods(self):
        """Test that _parse_response aggregates costs across multiple time periods."""
        client = CostExplorerClient()
        response = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                    'Groups': [
                        {
                            'Keys': ['AmazonEC2'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '1000.00', 'Unit': 'USD'}
                            }
                        }
                    ]
                },
                {
                    'TimePeriod': {'Start': '2024-02-01', 'End': '2024-03-01'},
                    'Groups': [
                        {
                            'Keys': ['AmazonEC2'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '234.56', 'Unit': 'USD'}
                            }
                        }
                    ]
                }
            ]
        }
        results = client._parse_response(response, 'service')
        assert len(results) == 1
        assert ('EC2', 1234.56) in results

    def test_parse_response_account_grouping(self):
        """Test _parse_response for account grouping (no translation)."""
        client = CostExplorerClient()
        response = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                    'Groups': [
                        {
                            'Keys': ['123456789012'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '1500.00', 'Unit': 'USD'}
                            }
                        }
                    ]
                }
            ]
        }
        results = client._parse_response(response, 'account')
        assert len(results) == 1
        assert ('123456789012', 1500.00) in results

    def test_parse_response_empty(self):
        """Test _parse_response with empty results."""
        client = CostExplorerClient()
        response = {
            'ResultsByTime': []
        }
        results = client._parse_response(response, 'service')
        assert results == []

    def test_get_costs_single_page(self):
        """Test get_costs with single page response."""
        client = CostExplorerClient()

        with Stubber(client.client) as stubber:
            response = {
                'GroupDefinitions': [
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ],
                'ResultsByTime': [
                    {
                        'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                        'Total': {
                            'UnblendedCost': {'Amount': '1800', 'Unit': 'USD'}
                        },
                        'Groups': [
                            {
                                'Keys': ['AmazonEC2'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '1234.56', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AmazonRDS'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '565.44', 'Unit': 'USD'}
                                }
                            }
                        ]
                    }
                ]
            }

            stubber.add_response('get_cost_and_usage', response)

            results = client.get_costs('2024-01-01', '2024-02-01', 'service')

            assert len(results) == 2
            assert ('EC2', 1234.56) in results
            assert ('RDS', 565.44) in results

    def test_get_costs_with_pagination(self):
        """Test get_costs with pagination."""
        client = CostExplorerClient()

        with Stubber(client.client) as stubber:
            # First page response
            response1 = {
                'GroupDefinitions': [
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ],
                'ResultsByTime': [
                    {
                        'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                        'Total': {
                            'UnblendedCost': {'Amount': '2000', 'Unit': 'USD'}
                        },
                        'Groups': [
                            {
                                'Keys': ['AmazonEC2'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '1000.00', 'Unit': 'USD'}
                                }
                            }
                        ]
                    }
                ],
                'NextPageToken': 'token123'
            }

            # Second page response
            response2 = {
                'GroupDefinitions': [
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ],
                'ResultsByTime': [
                    {
                        'TimePeriod': {'Start': '2024-01-01', 'End': '2024-02-01'},
                        'Total': {
                            'UnblendedCost': {'Amount': '1000', 'Unit': 'USD'}
                        },
                        'Groups': [
                            {
                                'Keys': ['AmazonRDS'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '1000.00', 'Unit': 'USD'}
                                }
                            }
                        ]
                    }
                ]
            }

            stubber.add_response('get_cost_and_usage', response1)
            stubber.add_response('get_cost_and_usage', response2)

            results = client.get_costs('2024-01-01', '2024-02-01', 'service')

            # Should have results from both pages
            assert len(results) == 2
            assert ('EC2', 1000.00) in results
            assert ('RDS', 1000.00) in results


# ============================================================================
# Tests for FixtureProvider
# ============================================================================

class TestFixtureProvider:
    """Test FixtureProvider class."""

    def test_fixture_service_grouping(self):
        """Test fixture for service grouping."""
        provider = FixtureProvider('service')
        output = provider.get_fixture_table()

        assert 'Service | Cost USD' in output
        assert 'EC2 | $1,234.56' in output
        assert 'RDS | $567.89' in output
        assert 'Lambda | $123.45' in output
        assert 'S3 | $89.10' in output
        assert 'TOTAL | $2,015.00' in output

    def test_fixture_account_grouping(self):
        """Test fixture for account grouping."""
        provider = FixtureProvider('account')
        output = provider.get_fixture_table()

        assert 'Account | Cost USD' in output
        assert '123456789012 | $1,500.00' in output
        assert '210987654321 | $800.00' in output
        assert '345678901234 | $715.00' in output
        assert 'TOTAL | $3,015.00' in output

    def test_fixture_linked_account_grouping(self):
        """Test fixture for linked-account grouping."""
        provider = FixtureProvider('linked-account')
        output = provider.get_fixture_table()

        assert 'Linked Account | Cost USD' in output
        assert '123456789012 | $1,500.00' in output
        assert 'TOTAL | $3,015.00' in output

    def test_fixture_tag_grouping(self):
        """Test fixture for tag grouping."""
        provider = FixtureProvider('tag:Environment')
        output = provider.get_fixture_table()

        assert 'Environment | Cost USD' in output
        assert 'production | $2,000.00' in output
        assert 'staging | $500.00' in output
        assert 'development | $300.00' in output
        assert 'TOTAL | $2,800.00' in output

    def test_fixture_determinism(self):
        """Test that fixture is deterministic (same output on multiple calls)."""
        provider1 = FixtureProvider('service')
        output1 = provider1.get_fixture_table()

        provider2 = FixtureProvider('service')
        output2 = provider2.get_fixture_table()

        assert output1 == output2

    def test_fixture_sorted_by_cost(self):
        """Test that fixture is sorted descending by cost."""
        provider = FixtureProvider('service')
        output = provider.get_fixture_table()

        lines = output.split('\n')
        data_lines = lines[2:-1]  # Skip header, separator, and total

        costs = []
        for line in data_lines:
            # Extract cost from line like "| EC2 | $1,234.56 |"
            parts = line.split('|')
            cost_str = parts[2].strip().replace('$', '').replace(',', '')
            costs.append(float(cost_str))

        # Check that costs are in descending order
        assert costs == sorted(costs, reverse=True)


# ============================================================================
# Tests for OutputFormatter
# ============================================================================

class TestOutputFormatter:
    """Test OutputFormatter class."""

    def test_format_table_service_grouping(self):
        """Test format_table for service grouping."""
        formatter = OutputFormatter()
        results = [
            ('EC2', 1234.56),
            ('Lambda', 12.34),
            ('RDS', 567.89),
        ]
        output = formatter.format_table(results, 'service')

        assert 'Service | Cost USD' in output
        assert 'EC2 | $1,234.56' in output
        assert 'RDS | $567.89' in output
        assert 'Lambda | $12.34' in output
        assert 'TOTAL | $1,814.79' in output

    def test_format_table_account_grouping(self):
        """Test format_table for account grouping."""
        formatter = OutputFormatter()
        results = [
            ('123456789012', 1500.00),
            ('210987654321', 800.00),
        ]
        output = formatter.format_table(results, 'account')

        assert 'Account | Cost USD' in output
        assert '123456789012 | $1,500.00' in output
        assert '210987654321 | $800.00' in output
        assert 'TOTAL | $2,300.00' in output

    def test_format_table_sorting(self):
        """Test that format_table sorts by cost descending."""
        formatter = OutputFormatter()
        results = [
            ('C', 100.00),
            ('B', 500.00),
            ('A', 250.00),
        ]
        output = formatter.format_table(results, 'service')

        lines = output.split('\n')
        # Line 0 is header, line 1 is separator, then data rows
        assert 'B | $500.00' in lines[2]
        assert 'A | $250.00' in lines[3]
        assert 'C | $100.00' in lines[4]

    def test_format_table_currency_formatting(self):
        """Test that format_table formats currency correctly."""
        formatter = OutputFormatter()
        results = [
            ('Service1', 1234567.89),
            ('Service2', 12.34),
            ('Service3', 0.01),
        ]
        output = formatter.format_table(results, 'service')

        assert '$1,234,567.89' in output
        assert '$12.34' in output
        assert '$0.01' in output

    def test_format_table_grand_total(self):
        """Test that grand total is calculated correctly."""
        formatter = OutputFormatter()
        results = [
            ('A', 100.00),
            ('B', 200.50),
            ('C', 50.25),
        ]
        output = formatter.format_table(results, 'service')

        assert 'TOTAL | $350.75' in output

    def test_format_table_empty_results(self):
        """Test format_table with empty results."""
        formatter = OutputFormatter()
        results = []
        output = formatter.format_table(results, 'service')

        assert 'Service | Cost USD' in output
        assert 'TOTAL | $0.00' in output

    def test_format_table_escape_pipe(self):
        """Test that pipe characters in dimension names are escaped."""
        formatter = OutputFormatter()
        results = [
            ('Service|Name', 100.00),
        ]
        output = formatter.format_table(results, 'service')

        # Pipe should be escaped
        assert 'Service\\|Name' in output

    def test_format_table_escape_backslash(self):
        """Test that backslash characters in dimension names are escaped."""
        formatter = OutputFormatter()
        results = [
            ('Service\\Name', 100.00),
        ]
        output = formatter.format_table(results, 'service')

        # Backslash should be escaped
        assert 'Service\\\\Name' in output

    def test_get_dimension_header_service(self):
        """Test _get_dimension_header for service."""
        formatter = OutputFormatter()
        assert formatter._get_dimension_header('service') == 'Service'

    def test_get_dimension_header_account(self):
        """Test _get_dimension_header for account."""
        formatter = OutputFormatter()
        assert formatter._get_dimension_header('account') == 'Account'

    def test_get_dimension_header_linked_account(self):
        """Test _get_dimension_header for linked-account."""
        formatter = OutputFormatter()
        assert formatter._get_dimension_header('linked-account') == 'Linked Account'

    def test_get_dimension_header_tag(self):
        """Test _get_dimension_header for tag dimensions."""
        formatter = OutputFormatter()
        assert formatter._get_dimension_header('tag:Environment') == 'Environment'
        assert formatter._get_dimension_header('tag:Application') == 'Application'


# ============================================================================
# Tests for main() entry point
# ============================================================================

class TestMain:
    """Test main() entry point."""

    def test_main_dry_run_service(self, capsys):
        """Test main with --dry-run --group-by service."""
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert 'Service | Cost USD' in captured.out
        assert 'EC2' in captured.out
        assert 'TOTAL' in captured.out

    def test_main_dry_run_account(self, capsys):
        """Test main with --dry-run --group-by account."""
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'account']):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert 'Account | Cost USD' in captured.out

    def test_main_dry_run_default_group_by(self, capsys):
        """Test main with --dry-run (uses default service grouping)."""
        with patch('sys.argv', ['query.py', '--dry-run']):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert 'Service | Cost USD' in captured.out

    def test_main_missing_required_args(self):
        """Test main fails when required args are missing."""
        with patch('sys.argv', ['query.py']):
            with pytest.raises(SystemExit):
                main()

    def test_main_missing_end_date(self):
        """Test main fails when --end is missing."""
        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--group-by', 'service']):
            with pytest.raises(SystemExit):
                main()

    def test_main_missing_start_date(self):
        """Test main fails when --start is missing."""
        with patch('sys.argv', ['query.py', '--end', '2024-03-31', '--group-by', 'service']):
            with pytest.raises(SystemExit):
                main()

    def test_main_missing_group_by(self):
        """Test main fails when --group-by is missing."""
        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31']):
            with pytest.raises(SystemExit):
                main()

    def test_main_invalid_date_format(self):
        """Test main rejects invalid date format."""
        with patch('sys.argv', ['query.py', '--start', '2024-01', '--end', '2024-03-31', '--group-by', 'service']):
            with pytest.raises(SystemExit):
                main()

    def test_main_invalid_group_by(self):
        """Test main rejects invalid group-by."""
        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'invalid']):
            with pytest.raises(SystemExit):
                main()

    @patch('query.CostExplorerClient')
    def test_main_no_credentials_error(self, mock_client_class, capsys):
        """Test main handles NoCredentialsError."""
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance
        mock_instance.get_costs.side_effect = NoCredentialsError()

        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert 'Error: AWS credentials not found' in captured.out

    @patch('query.CostExplorerClient')
    def test_main_unauthorized_operation_error(self, mock_client_class, capsys):
        """Test main handles UnauthorizedOperation ClientError."""
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance

        error = ClientError(
            {'Error': {'Code': 'UnauthorizedOperation'}},
            'GetCostAndUsage'
        )
        mock_instance.get_costs.side_effect = error

        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert 'Error: AWS Cost Explorer API access denied' in captured.out

    @patch('query.CostExplorerClient')
    def test_main_success_with_stubbed_results(self, mock_client_class, capsys):
        """Test main successfully formats results from CostExplorerClient."""
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance
        mock_instance.get_costs.return_value = [
            ('EC2', 1234.56),
            ('RDS', 567.89),
        ]

        with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert 'EC2 | $1,234.56' in captured.out
        assert 'RDS | $567.89' in captured.out
        assert 'TOTAL' in captured.out
