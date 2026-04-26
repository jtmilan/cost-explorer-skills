"""
Integration tests for merged features: pytest-tests and documentation-readme.

These tests verify:
1. Documentation examples execute correctly
2. README expected outputs match actual outputs
3. Error messages match documented behavior
4. Fixture data is consistent with documentation
5. All grouping dimensions work end-to-end
6. Main entry point integrates all components correctly
"""

import pytest
from botocore.stub import Stubber
import sys
import os
from unittest.mock import patch, MagicMock
import re
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

CostExplorerClient = query_module.CostExplorerClient
FixtureProvider = query_module.FixtureProvider
OutputFormatter = query_module.OutputFormatter
main = query_module.main


class TestReadmeExampleIntegration:
    """
    Integration tests verifying README examples work as documented.

    These tests execute the exact commands from README.md and verify outputs
    match the documented expected outputs.
    """

    def test_readme_example_1_service_grouping(self, capsys):
        """
        Test README Example 1: --dry-run --group-by service

        Expected output from README:
        | Service | Cost USD |
        |---------|----------|
        | EC2 | $1,234.56 |
        | RDS | $567.89 |
        | Lambda | $123.45 |
        | S3 | $89.10 |
        | TOTAL | $2,015.00 |
        """
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result = main()

        assert result == 0, "Example 1 should exit with code 0"
        captured = capsys.readouterr()

        # Verify all expected lines from README
        assert '| Service | Cost USD |' in captured.out
        assert '| EC2 | $1,234.56 |' in captured.out
        assert '| RDS | $567.89 |' in captured.out
        assert '| Lambda | $123.45 |' in captured.out
        assert '| S3 | $89.10 |' in captured.out
        assert '| TOTAL | $2,015.00 |' in captured.out

        # Verify markdown table structure
        lines = captured.out.strip().split('\n')
        assert lines[0].startswith('|')
        assert '|' in captured.out

    def test_readme_example_2_account_grouping(self, capsys):
        """
        Test README Example 2: --dry-run --group-by account

        Expected output from README:
        | Account | Cost USD |
        |---------|----------|
        | 123456789012 | $1,500.00 |
        | 210987654321 | $800.00 |
        | 345678901234 | $715.00 |
        | TOTAL | $3,015.00 |
        """
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'account']):
            result = main()

        assert result == 0, "Example 2 should exit with code 0"
        captured = capsys.readouterr()

        # Verify all expected lines from README
        assert '| Account | Cost USD |' in captured.out
        assert '| 123456789012 | $1,500.00 |' in captured.out
        assert '| 210987654321 | $800.00 |' in captured.out
        assert '| 345678901234 | $715.00 |' in captured.out
        assert '| TOTAL | $3,015.00 |' in captured.out

    def test_readme_example_3_linked_account_grouping(self, capsys):
        """
        Test README Example 3: --dry-run --start 2024-01-01 --end 2024-03-31 --group-by linked-account

        Expected output from README:
        | Linked Account | Cost USD |
        |----------------|----------|
        | 123456789012 | $1,500.00 |
        | 210987654321 | $800.00 |
        | 345678901234 | $715.00 |
        | TOTAL | $3,015.00 |
        """
        with patch('sys.argv', ['query.py', '--dry-run', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'linked-account']):
            result = main()

        assert result == 0, "Example 3 should exit with code 0"
        captured = capsys.readouterr()

        # Verify all expected lines from README
        assert '| Linked Account | Cost USD |' in captured.out
        assert '| 123456789012 | $1,500.00 |' in captured.out
        assert '| 210987654321 | $800.00 |' in captured.out
        assert '| 345678901234 | $715.00 |' in captured.out
        assert '| TOTAL | $3,015.00 |' in captured.out


class TestFixtureDocumentationConsistency:
    """
    Integration tests verifying fixture data matches documentation.
    """

    def test_fixture_matches_readme_example_1_values(self):
        """Verify fixture values match README Example 1 expected output."""
        provider = FixtureProvider('service')
        output = provider.get_fixture_table()

        # Values from README Example 1
        assert 'EC2 | $1,234.56' in output
        assert 'RDS | $567.89' in output
        assert 'Lambda | $123.45' in output
        assert 'S3 | $89.10' in output
        assert 'TOTAL | $2,015.00' in output

    def test_fixture_matches_readme_example_2_values(self):
        """Verify fixture values match README Example 2 expected output."""
        provider = FixtureProvider('account')
        output = provider.get_fixture_table()

        # Values from README Example 2
        assert '123456789012 | $1,500.00' in output
        assert '210987654321 | $800.00' in output
        assert '345678901234 | $715.00' in output
        assert 'TOTAL | $3,015.00' in output

    def test_fixture_matches_readme_example_3_values(self):
        """Verify fixture values match README Example 3 expected output."""
        provider = FixtureProvider('linked-account')
        output = provider.get_fixture_table()

        # Values from README Example 3
        assert '123456789012 | $1,500.00' in output
        assert '210987654321 | $800.00' in output
        assert '345678901234 | $715.00' in output
        assert 'TOTAL | $3,015.00' in output


class TestOutputFormattingConsistency:
    """
    Integration tests verifying output formatting is consistent across all dimensions.
    """

    def test_all_dimensions_use_markdown_table_format(self):
        """Verify all grouping dimensions produce valid markdown tables."""
        dimensions = ['service', 'account', 'linked-account', 'tag:Environment']

        for dim in dimensions:
            provider = FixtureProvider(dim)
            output = provider.get_fixture_table()

            # All tables should:
            # 1. Have pipe separators
            assert '|' in output, f"Dimension {dim} missing pipe separators"
            # 2. Have header row
            assert 'Cost USD' in output, f"Dimension {dim} missing Cost USD header"
            # 3. Have TOTAL row
            assert 'TOTAL' in output, f"Dimension {dim} missing TOTAL row"
            # 4. Have separator row (dashes between header and data)
            assert '----' in output, f"Dimension {dim} missing separator row"

    def test_currency_format_consistent_across_dimensions(self):
        """Verify currency formatting ($X,XXX.XX) is consistent across all dimensions."""
        dimensions = ['service', 'account', 'linked-account']

        for dim in dimensions:
            provider = FixtureProvider(dim)
            output = provider.get_fixture_table()

            # Find all currency amounts using regex
            amounts = re.findall(r'\$[\d,]+\.\d{2}', output)
            assert len(amounts) > 1, f"Dimension {dim}: Expected multiple currency amounts"

            # Verify format: $ + optional commas + decimal point + 2 digits
            for amount in amounts:
                assert re.match(r'\$[\d,]+\.\d{2}$', amount), \
                    f"Dimension {dim}: Invalid currency format '{amount}'"

    def test_sorting_consistent_across_dimensions(self):
        """Verify all outputs are sorted descending by cost."""
        # Test with actual results from OutputFormatter
        formatter = OutputFormatter()

        # Service grouping
        service_results = [('Lambda', 12.34), ('EC2', 1234.56), ('RDS', 567.89)]
        service_output = formatter.format_table(service_results, 'service')
        # Filter to data lines only (not header or separator)
        service_lines = []
        for line in service_output.split('\n'):
            if '|' in line and 'Cost' not in line and '---' not in line and 'TOTAL' not in line:
                service_lines.append(line)
        assert '$1,234.56' in service_lines[0], "EC2 (highest) should be first"

        # Account grouping
        account_results = [('acc2', 100.0), ('acc1', 500.0)]
        account_output = formatter.format_table(account_results, 'account')
        account_lines = []
        for line in account_output.split('\n'):
            if '|' in line and 'Cost' not in line and '---' not in line and 'TOTAL' not in line:
                account_lines.append(line)
        assert '$500.00' in account_lines[0], "Highest cost should be first"


class TestCrossComponentIntegration:
    """
    Integration tests verifying how components work together.
    """

    def test_validator_group_by_integrates_with_fixture_provider(self):
        """Verify that all valid group-by values accepted by validator work with FixtureProvider."""
        from query import validate_group_by

        valid_values = ['service', 'account', 'linked-account', 'tag:Environment', 'tag:App']

        for group_by in valid_values:
            # Validator should accept it
            assert validate_group_by(group_by) == group_by

            # FixtureProvider should work with it
            provider = FixtureProvider(group_by)
            output = provider.get_fixture_table()
            assert output is not None
            assert 'TOTAL' in output
            assert '|' in output

    def test_main_integrates_fixture_provider_correctly(self, capsys):
        """
        Verify main() correctly integrates FixtureProvider for --dry-run mode.
        """
        # When main() runs with --dry-run, it should use FixtureProvider
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result = main()

        captured = capsys.readouterr()

        # Verify the output is from FixtureProvider (contains exact fixture values)
        assert 'EC2 | $1,234.56' in captured.out
        assert result == 0

    def test_formatter_dimension_headers_match_specifications(self):
        """Verify OutputFormatter produces correct headers for all dimensions."""
        formatter = OutputFormatter()

        test_cases = [
            ('service', 'Service'),
            ('account', 'Account'),
            ('linked-account', 'Linked Account'),
            ('tag:Environment', 'Environment'),
            ('tag:CostCenter', 'CostCenter'),
        ]

        for group_by, expected_header in test_cases:
            header = formatter._get_dimension_header(group_by)
            assert header == expected_header, f"Header mismatch for {group_by}"


class TestMergeConflictAreas:
    """
    Integration tests targeting the merge areas.

    Focus on interactions between:
    - test_query.py (comprehensive test suite)
    - README.md (documentation with examples)
    - query.py (core implementation)
    """

    def test_readme_examples_all_pass_in_test_context(self, capsys):
        """
        Verify all 3 README examples execute without errors in test context.
        This tests the integration of README documentation with actual code.
        """
        examples = [
            (['--dry-run', '--group-by', 'service'], 'Example 1'),
            (['--dry-run', '--group-by', 'account'], 'Example 2'),
            (['--dry-run', '--start', '2024-01-01', '--end', '2024-03-31', '--group-by', 'linked-account'], 'Example 3'),
        ]

        for args, example_name in examples:
            with patch('sys.argv', ['query.py'] + args):
                result = main()

            assert result == 0, f"{example_name} failed with exit code {result}"
            captured = capsys.readouterr()
            assert 'TOTAL |' in captured.out, f"{example_name} missing TOTAL row"
            assert 'Cost USD' in captured.out, f"{example_name} missing header"

    def test_documented_dimensions_all_supported(self):
        """
        Verify all dimensions documented in README are supported end-to-end.
        From README: service, account, linked-account, tag:<name>
        """
        from query import validate_group_by

        documented_dims = [
            ('service', 'AWS service (e.g., EC2, RDS, Lambda, S3)'),
            ('account', 'Payer account (AWS account number)'),
            ('linked-account', 'Linked account in consolidated billing'),
            ('tag:Environment', 'Custom tag key'),
        ]

        for dim, description in documented_dims:
            # 1. Validator should accept it
            assert validate_group_by(dim) == dim, f"Validator rejected {dim}"

            # 2. FixtureProvider should handle it
            provider = FixtureProvider(dim)
            fixture_output = provider.get_fixture_table()
            assert fixture_output, f"FixtureProvider failed for {dim}"

            # 3. OutputFormatter should handle it
            formatter = OutputFormatter()
            test_results = [('test_value', 100.0)]
            formatted_output = formatter.format_table(test_results, dim)
            assert formatted_output, f"OutputFormatter failed for {dim}"

    def test_help_text_matches_usage_in_readme(self, capsys):
        """
        Verify that argparse help output matches the usage section in README.
        """
        with patch('sys.argv', ['query.py', '--help']):
            with pytest.raises(SystemExit):  # argparse calls sys.exit on --help
                main()

        captured = capsys.readouterr()
        help_text = captured.out

        # Verify key elements from README Usage section are in help
        assert '--start' in help_text
        assert '--end' in help_text
        assert '--group-by' in help_text
        assert '--dry-run' in help_text
        assert 'YYYY-MM-DD' in help_text
        assert 'service' in help_text
        assert 'account' in help_text


class TestEndToEndScenarios:
    """
    End-to-end integration tests simulating real usage scenarios.
    """

    def test_user_scenario_dry_run_exploration(self, capsys):
        """
        Scenario: User wants to explore service costs without AWS access.
        Steps:
        1. Run with --dry-run --group-by service
        2. Examine output structure
        3. Verify they can understand the format
        """
        with patch('sys.argv', ['query.py', '--dry-run', '--group-by', 'service']):
            result = main()

        captured = capsys.readouterr()
        output = captured.out

        # User should see:
        # 1. Readable header
        assert 'Service | Cost USD' in output, "Header should be clear"

        # 2. Multiple services with costs
        assert 'EC2' in output and '$' in output, "Should show service names and costs"

        # 3. Grand total for understanding total spend
        assert 'TOTAL | $' in output, "Should show total spend"

        # 4. No errors
        assert result == 0, "Should not error in dry-run mode"

    def test_user_scenario_multiple_dimension_queries(self, capsys):
        """
        Scenario: User wants to analyze costs from different perspectives.
        Steps:
        1. Query by service
        2. Query by account
        3. Query by linked-account
        Verify all three perspectives work consistently.
        """
        dimensions_tested = []

        for dim, args in [
            ('service', ['--dry-run', '--group-by', 'service']),
            ('account', ['--dry-run', '--group-by', 'account']),
            ('linked-account', ['--dry-run', '--group-by', 'linked-account']),
        ]:
            with patch('sys.argv', ['query.py'] + args):
                result = main()

            assert result == 0, f"Failed for dimension: {dim}"
            captured = capsys.readouterr()

            # All should have consistent structure
            assert 'Cost USD' in captured.out
            assert 'TOTAL |' in captured.out
            dimensions_tested.append(dim)

        assert len(dimensions_tested) == 3, "All three dimensions should be tested"

    def test_dry_run_mode_independence(self, capsys):
        """
        Scenario: Dry-run mode should work without any AWS access or credentials.
        Verify that --dry-run does not attempt AWS calls.
        """
        # This should work even though no real AWS credentials are configured
        with patch('sys.argv', ['query.py', '--dry-run']):
            result = main()

        captured = capsys.readouterr()
        assert result == 0, "Dry-run should succeed without AWS credentials"
        assert 'TOTAL' in captured.out, "Should get output"


class TestClientIntegrationWithValidator:
    """
    Tests verifying CostExplorerClient correctly integrates with argument validation.
    """

    def test_parse_group_by_converts_all_valid_cli_formats_to_aws_format(self):
        """
        Verify that CostExplorerClient._parse_group_by correctly translates
        all valid CLI format group-by strings to AWS API format.
        """
        client = CostExplorerClient()

        test_cases = [
            ('service', [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]),
            ('account', [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]),
            ('linked-account', [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]),
            ('tag:Environment', [{'Type': 'TAG', 'Key': 'Environment'}]),
            ('tag:CostCenter', [{'Type': 'TAG', 'Key': 'CostCenter'}]),
        ]

        for cli_format, expected_aws_format in test_cases:
            result = client._parse_group_by(cli_format)
            assert result == expected_aws_format, \
                f"Failed to convert {cli_format} to AWS format"

    def test_service_name_translation_matches_aws_responses(self):
        """
        Verify that service name translation matches AWS Cost Explorer's
        actual service ID responses.
        """
        client = CostExplorerClient()

        # These are actual AWS service IDs from Cost Explorer
        test_cases = [
            ('AmazonEC2', 'EC2'),
            ('AmazonRDS', 'RDS'),
            ('AWSLambda', 'Lambda'),
            ('AmazonSimpleStorageService', 'S3'),
            ('AWSDataTransfer', 'Data Transfer'),
        ]

        for aws_id, expected_display in test_cases:
            result = client._translate_service_name(aws_id)
            assert result == expected_display, \
                f"Service translation failed for {aws_id}"
