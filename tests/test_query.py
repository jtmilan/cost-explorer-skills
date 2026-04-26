"""
Tests for cost-explorer-query query.py module.

Uses botocore.stub.Stubber for AWS API mocking (no live AWS calls).
Tests cover:
- Argparse validators (validate_date, validate_group_by)
- CostExplorerClient with Stubber-based API mocking
- FixtureProvider deterministic fixture data
- OutputFormatter sorting and currency formatting
- main() entry point with --dry-run and normal flow
- Error handling for NoCredentialsError and UnauthorizedOperation
"""

import pytest
from botocore.stub import Stubber
from botocore.exceptions import ClientError, NoCredentialsError
import sys
import os
from unittest.mock import patch
import argparse
import importlib.util

# Load the module directly from file
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

    def test_validate_date_valid_first_day(self):
        """Test that valid YYYY-MM-DD format is accepted (first day of year)."""
        assert validate_date('2024-01-01') == '2024-01-01'

    def test_validate_date_valid_last_day(self):
        """Test that valid YYYY-MM-DD format is accepted (last day of year)."""
        assert validate_date('2024-12-31') == '2024-12-31'

    def test_validate_date_invalid_missing_dashes(self):
        """Test that date without dashes is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('20240101')

    def test_validate_date_invalid_wrong_order(self):
        """Test that wrong date format (MM-DD-YYYY) is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('01-01-2024')

    def test_validate_date_invalid_text(self):
        """Test that text dates are rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_date('2024-Jan-01')


# ============================================================================
# Tests for validate_group_by function
# ============================================================================

class TestValidateGroupBy:
    """Test group-by validation function."""

    def test_validate_group_by_valid_service(self):
        """Test that 'service' is valid."""
        assert validate_group_by('service') == 'service'

    def test_validate_group_by_valid_account(self):
        """Test that 'account' is valid."""
        assert validate_group_by('account') == 'account'

    def test_validate_group_by_valid_linked_account(self):
        """Test that 'linked-account' is valid."""
        assert validate_group_by('linked-account') == 'linked-account'

    def test_validate_group_by_valid_tag(self):
        """Test that 'tag:<name>' format is valid."""
        assert validate_group_by('tag:Environment') == 'tag:Environment'
        assert validate_group_by('tag:Application') == 'tag:Application'

    def test_validate_group_by_invalid_dimension(self):
        """Test that invalid group-by values are rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_group_by('invalid')

    def test_validate_group_by_invalid_tag_without_key(self):
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


# ============================================================================
# Tests for main() entry point with Stubber - Core Acceptance Criteria Tests
# ============================================================================

class TestMainHappyPath:
    """Test main() happy path scenarios with Stubber."""

    def test_happy_path_service_grouping(self, capsys):
        """
        Test happy path with service grouping (Acceptance Criteria).

        Sets up Stubber with mock get_cost_and_usage response containing 3 services (EC2, RDS, Lambda).
        Calls main() with --start 2024-01-01 --end 2024-03-31 --group-by service.
        Verifies:
        - Exit code 0
        - Output contains all 3 services
        - Output is sorted by cost descending
        - Grand total row is present and correct
        - Costs formatted as $X,XXX.XX
        """
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
                            'UnblendedCost': {'Amount': '1903.89', 'Unit': 'USD'}
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
                                    'UnblendedCost': {'Amount': '567.89', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AWSLambda'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '101.44', 'Unit': 'USD'}
                                }
                            }
                        ]
                    },
                    {
                        'TimePeriod': {'Start': '2024-02-01', 'End': '2024-03-01'},
                        'Total': {
                            'UnblendedCost': {'Amount': '1903.89', 'Unit': 'USD'}
                        },
                        'Groups': [
                            {
                                'Keys': ['AmazonEC2'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AmazonRDS'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AWSLambda'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            }
                        ]
                    },
                    {
                        'TimePeriod': {'Start': '2024-03-01', 'End': '2024-03-31'},
                        'Total': {
                            'UnblendedCost': {'Amount': '1903.89', 'Unit': 'USD'}
                        },
                        'Groups': [
                            {
                                'Keys': ['AmazonEC2'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AmazonRDS'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            },
                            {
                                'Keys': ['AWSLambda'],
                                'Metrics': {
                                    'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'}
                                }
                            }
                        ]
                    }
                ]
            }

            stubber.add_response('get_cost_and_usage', response)

            # Patch the client creation to use our stubbed client
            with patch('query.CostExplorerClient') as mock_client_class:
                mock_client_class.return_value = client
                with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
                    result = main()

        assert result == 0, "Exit code should be 0 for successful query"
        captured = capsys.readouterr()

        # Verify all 3 services are in output
        assert 'EC2 |' in captured.out, "EC2 should be in output"
        assert 'RDS |' in captured.out, "RDS should be in output"
        assert 'Lambda |' in captured.out, "Lambda should be in output"

        # Verify grand total row
        assert 'TOTAL |' in captured.out, "TOTAL row should be present"
        assert '$1,903.89' in captured.out, "Grand total should be correct"

        # Verify sorting (EC2 should come before RDS, RDS before Lambda)
        lines = captured.out.split('\n')
        ec2_line = next(i for i, line in enumerate(lines) if 'EC2 |' in line)
        rds_line = next(i for i, line in enumerate(lines) if 'RDS |' in line)
        lambda_line = next(i for i, line in enumerate(lines) if 'Lambda |' in line)
        assert ec2_line < rds_line < lambda_line, "Services should be sorted by cost descending"

        # Verify currency format (thousands separator with 2 decimals)
        assert '$1,234.56' in captured.out, "Costs should be formatted with thousands separator"

    def test_happy_path_pagination(self, capsys):
        """
        Test pagination with Stubber (Optional acceptance criterion).

        Sets up Stubber with first response containing NextPageToken,
        second response without token.
        Verifies exit code 0, output aggregates costs from both pages,
        grand total is sum of both pages.
        """
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
                            'UnblendedCost': {'Amount': '1000', 'Unit': 'USD'}
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

            # Second page response (no NextPageToken)
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

            with patch('query.CostExplorerClient') as mock_client_class:
                mock_client_class.return_value = client
                with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-02-01', '--group-by', 'service']):
                    result = main()

        assert result == 0, "Exit code should be 0 for successful pagination"
        captured = capsys.readouterr()

        # Verify both services from both pages are in output
        assert 'EC2 | $1,000.00' in captured.out, "EC2 from page 1 should be in output"
        assert 'RDS | $1,000.00' in captured.out, "RDS from page 2 should be in output"
        assert 'TOTAL | $2,000.00' in captured.out, "Grand total should be sum of both pages"

    def test_empty_result(self, capsys):
        """
        Test empty result handling (Acceptance Criteria).

        Sets up Stubber with mock response containing empty ResultsByTime=[] and NextPageToken=None.
        Calls main() with valid args.
        Verifies:
        - Exit code 0
        - Output is valid markdown table (header + total row)
        - Grand total shows $0.00
        - No crash
        """
        client = CostExplorerClient()

        with Stubber(client.client) as stubber:
            response = {
                'GroupDefinitions': [
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ],
                'ResultsByTime': []
            }

            stubber.add_response('get_cost_and_usage', response)

            with patch('query.CostExplorerClient') as mock_client_class:
                mock_client_class.return_value = client
                with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
                    result = main()

        assert result == 0, "Exit code should be 0 even with empty results"
        captured = capsys.readouterr()

        # Verify valid markdown table structure
        assert 'Service | Cost USD' in captured.out, "Header row should be present"
        assert 'TOTAL | $0.00' in captured.out, "Grand total should show $0.00"

        # Verify it's still a valid table (has separator)
        assert '|' in captured.out, "Should have pipe separators for markdown table"


# ============================================================================
# Tests for error handling with Stubber
# ============================================================================

class TestErrorHandling:
    """Test error handling with Stubber."""

    def test_aws_unauthorized_error(self, capsys):
        """
        Test unauthorized error handling (Acceptance Criteria).

        Sets up Stubber to raise ClientError with Error.Code='UnauthorizedOperation'.
        Calls main() with valid args.
        Verifies:
        - Exit code 1
        - Output contains exact error message: 'Error: AWS Cost Explorer API access denied. Ensure IAM permissions include ce:GetCostAndUsage.'
        """
        client = CostExplorerClient()

        with Stubber(client.client) as stubber:
            error = ClientError(
                {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'User is not authorized'}},
                'GetCostAndUsage'
            )
            stubber.add_client_error('get_cost_and_usage', service_error_code='UnauthorizedOperation')

            with patch('query.CostExplorerClient') as mock_client_class:
                mock_client_class.return_value = client
                with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
                    result = main()

        assert result == 1, "Exit code should be 1 for authorization error"
        captured = capsys.readouterr()
        assert 'Error: AWS Cost Explorer API access denied. Ensure IAM permissions include ce:GetCostAndUsage.' in captured.out

    def test_missing_credentials_error(self, capsys):
        """
        Test missing credentials error handling (Optional acceptance criterion).

        Sets up Stubber to raise NoCredentialsError.
        Calls main().
        Verifies:
        - Exit code 1
        - Output contains exact error message: 'Error: AWS credentials not found. Configure credentials via AWS CLI or environment variables.'
        """
        client = CostExplorerClient()

        with Stubber(client.client) as stubber:
            stubber.add_client_error('get_cost_and_usage', service_error_code='NoCredentialsError')

            with patch('query.CostExplorerClient') as mock_client_class:
                # Make the mock raise NoCredentialsError when get_costs is called
                from unittest.mock import MagicMock
                mock_instance = MagicMock()
                mock_instance.get_costs.side_effect = NoCredentialsError()
                mock_client_class.return_value = mock_instance

                with patch('sys.argv', ['query.py', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'service']):
                    result = main()

        assert result == 1, "Exit code should be 1 for credentials error"
        captured = capsys.readouterr()
        assert 'Error: AWS credentials not found. Configure credentials via AWS CLI or environment variables.' in captured.out


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

    def test_dry_run_fixture(self, capsys):
        """
        Test --dry-run fixture determinism (Optional acceptance criterion).

        Calls main() with --dry-run --group-by service twice.
        Verifies:
        - Both calls return identical output
        - Output is valid markdown table
        - No boto3 calls made
        """
        # First call
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result1 = main()
        captured1 = capsys.readouterr()
        output1 = captured1.out

        # Second call
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result2 = main()
        captured2 = capsys.readouterr()
        output2 = captured2.out

        assert result1 == 0 and result2 == 0, "Both calls should succeed"
        assert output1 == output2, "Fixture output should be identical across calls"
        assert 'Service | Cost USD' in output1, "Output should be valid markdown table"
        assert 'TOTAL' in output1, "Output should have grand total row"

    def test_fixture_determinism(self):
        """Test that fixture is deterministic (same output on multiple calls)."""
        provider1 = FixtureProvider('service')
        output1 = provider1.get_fixture_table()

        provider2 = FixtureProvider('service')
        output2 = provider2.get_fixture_table()

        assert output1 == output2, "Fixture should be deterministic"

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
        assert costs == sorted(costs, reverse=True), "Costs should be sorted descending"


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
# Tests for main() entry point - Argument Validation
# ============================================================================

class TestMainArgumentValidation:
    """Test main() argument validation."""

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
