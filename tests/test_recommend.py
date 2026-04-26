"""
Tests for finops-recommend recommend.py module.

Tests cover:
- Finding dataclass instantiation and field types
- RuleResult dataclass instantiation and field types
- FixtureProvider.get_fixture_results() returns 4 results (one per rule)
- FixtureProvider.get_fixture_results_for_rules() filters correctly
- Schema validation (ARN prefix, float savings, 'aws ' command prefix)
- IdleEc2Rule with botocore.stub.Stubber for AWS API mocking
"""

import pytest
import sys
import os
import importlib.util
from datetime import datetime, timezone, timedelta
from unittest.mock import patch


# Load the recommend module directly from file (handles hyphenated path)
recommend_module_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'skills',
    'finops-recommend',
    'recommend.py'
)

spec = importlib.util.spec_from_file_location("recommend", recommend_module_path)
recommend_module = importlib.util.module_from_spec(spec)
sys.modules['recommend'] = recommend_module
spec.loader.exec_module(recommend_module)

# Import classes under test
Finding = recommend_module.Finding
RuleResult = recommend_module.RuleResult
FixtureProvider = recommend_module.FixtureProvider
ReportGenerator = recommend_module.ReportGenerator
BaseRule = recommend_module.BaseRule
IdleEc2Rule = recommend_module.IdleEc2Rule
CPU_THRESHOLD = recommend_module.CPU_THRESHOLD
LOOKBACK_DAYS = recommend_module.LOOKBACK_DAYS
INSTANCE_PRICING = recommend_module.INSTANCE_PRICING
OversizedRdsRule = recommend_module.OversizedRdsRule
OrphanEbsRule = recommend_module.OrphanEbsRule


# ============================================================================
# Tests for Finding Dataclass
# ============================================================================

class TestFinding:
    """Test Finding dataclass instantiation and fields."""

    def test_finding_instantiation(self):
        """Test Finding dataclass instantiation with all fields."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="EC2 instance i-12345678 has 2.3% avg CPU over 7d",
            est_monthly_saved_usd=156.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )

        assert finding.arn == "arn:aws:ec2:us-east-1:123456789012:instance/i-12345678"
        assert finding.finding == "EC2 instance i-12345678 has 2.3% avg CPU over 7d"
        assert finding.est_monthly_saved_usd == 156.00
        assert finding.fix_command == "aws ec2 stop-instances --instance-ids i-12345678"

    def test_finding_field_count(self):
        """Test Finding has exactly 4 fields."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="Test finding",
            est_monthly_saved_usd=100.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )
        fields = finding.__dataclass_fields__
        assert len(fields) == 4
        assert set(fields.keys()) == {'arn', 'finding', 'est_monthly_saved_usd', 'fix_command'}

    def test_finding_arn_is_string(self):
        """Test Finding.arn is a string."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="Test finding",
            est_monthly_saved_usd=100.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )
        assert isinstance(finding.arn, str)

    def test_finding_est_monthly_saved_usd_is_float(self):
        """Test Finding.est_monthly_saved_usd is a float."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="Test finding",
            est_monthly_saved_usd=100.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )
        assert isinstance(finding.est_monthly_saved_usd, float)

    def test_finding_fix_command_is_string(self):
        """Test Finding.fix_command is a string."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="Test finding",
            est_monthly_saved_usd=100.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )
        assert isinstance(finding.fix_command, str)

    def test_finding_zero_savings(self):
        """Test Finding with zero savings (tag compliance case)."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-untagged",
            finding="Resources missing required tags: Environment, CostCenter",
            est_monthly_saved_usd=0.00,
            fix_command="aws ec2 create-tags --resources i-untagged --tags Key=Environment,Value=TBD"
        )
        assert finding.est_monthly_saved_usd == 0.00


# ============================================================================
# Tests for RuleResult Dataclass
# ============================================================================

class TestRuleResult:
    """Test RuleResult dataclass instantiation and fields."""

    def test_rule_result_instantiation_success(self):
        """Test RuleResult dataclass instantiation on success (no error)."""
        finding = Finding(
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-12345678",
            finding="Test finding",
            est_monthly_saved_usd=100.00,
            fix_command="aws ec2 stop-instances --instance-ids i-12345678"
        )
        result = RuleResult(
            rule_id="idle-ec2",
            findings=[finding],
            error=None
        )

        assert result.rule_id == "idle-ec2"
        assert len(result.findings) == 1
        assert result.findings[0] == finding
        assert result.error is None

    def test_rule_result_instantiation_failure(self):
        """Test RuleResult dataclass instantiation on failure (with error)."""
        result = RuleResult(
            rule_id="idle-ec2",
            findings=[],
            error="AccessDeniedException: User not authorized"
        )

        assert result.rule_id == "idle-ec2"
        assert len(result.findings) == 0
        assert result.error == "AccessDeniedException: User not authorized"

    def test_rule_result_field_count(self):
        """Test RuleResult has exactly 3 fields."""
        result = RuleResult(
            rule_id="idle-ec2",
            findings=[],
            error=None
        )
        fields = result.__dataclass_fields__
        assert len(fields) == 3
        assert set(fields.keys()) == {'rule_id', 'findings', 'error'}

    def test_rule_result_findings_is_list(self):
        """Test RuleResult.findings is a list."""
        result = RuleResult(
            rule_id="idle-ec2",
            findings=[],
            error=None
        )
        assert isinstance(result.findings, list)

    def test_rule_result_error_is_optional_string(self):
        """Test RuleResult.error is Optional[str]."""
        result_success = RuleResult(rule_id="idle-ec2", findings=[], error=None)
        result_failure = RuleResult(rule_id="idle-ec2", findings=[], error="Some error")

        assert result_success.error is None
        assert isinstance(result_failure.error, str)

    def test_rule_result_empty_findings(self):
        """Test RuleResult with empty findings (no issues found)."""
        result = RuleResult(
            rule_id="orphan-ebs",
            findings=[],
            error=None
        )
        assert len(result.findings) == 0
        assert result.error is None

    def test_rule_result_multiple_findings(self):
        """Test RuleResult with multiple findings."""
        findings = [
            Finding(
                arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1",
                finding="Finding 1",
                est_monthly_saved_usd=100.00,
                fix_command="aws ec2 stop-instances --instance-ids i-1"
            ),
            Finding(
                arn="arn:aws:ec2:us-east-1:123456789012:instance/i-2",
                finding="Finding 2",
                est_monthly_saved_usd=200.00,
                fix_command="aws ec2 stop-instances --instance-ids i-2"
            )
        ]
        result = RuleResult(
            rule_id="idle-ec2",
            findings=findings,
            error=None
        )
        assert len(result.findings) == 2


# ============================================================================
# Tests for FixtureProvider Class
# ============================================================================

class TestFixtureProvider:
    """Test FixtureProvider class for --dry-run mode."""

    def test_fixture_provider_returns_four_results(self):
        """Test get_fixture_results() returns exactly 4 RuleResult objects."""
        results = FixtureProvider.get_fixture_results()
        assert len(results) == 4

    def test_fixture_provider_returns_list_of_rule_results(self):
        """Test get_fixture_results() returns a List[RuleResult]."""
        results = FixtureProvider.get_fixture_results()
        assert isinstance(results, list)
        for result in results:
            assert isinstance(result, RuleResult)

    def test_fixture_provider_determinism(self):
        """Test get_fixture_results() is deterministic (identical on repeated calls)."""
        results1 = FixtureProvider.get_fixture_results()
        results2 = FixtureProvider.get_fixture_results()
        results3 = FixtureProvider.get_fixture_results()

        assert len(results1) == len(results2) == len(results3) == 4

        for r1, r2, r3 in zip(results1, results2, results3):
            assert r1.rule_id == r2.rule_id == r3.rule_id
            assert len(r1.findings) == len(r2.findings) == len(r3.findings)

    def test_fixture_provider_all_four_rules_present(self):
        """Test all 4 rule IDs are present in fixture results."""
        results = FixtureProvider.get_fixture_results()
        rule_ids = {r.rule_id for r in results}
        expected_rule_ids = {"idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"}
        assert rule_ids == expected_rule_ids

    def test_fixture_provider_each_rule_has_one_finding(self):
        """Test each fixture rule has exactly one finding."""
        results = FixtureProvider.get_fixture_results()
        for result in results:
            assert len(result.findings) == 1, f"Rule {result.rule_id} should have exactly 1 finding"

    def test_fixture_provider_no_errors(self):
        """Test all fixture results have error=None (no errors)."""
        results = FixtureProvider.get_fixture_results()
        for result in results:
            assert result.error is None, f"Rule {result.rule_id} should have no error"

    def test_fixture_provider_schema_validation_arn_prefix(self):
        """Test all fixture ARNs start with 'arn:aws:'."""
        results = FixtureProvider.get_fixture_results()
        for result in results:
            for finding in result.findings:
                assert finding.arn.startswith("arn:aws:"), (
                    f"ARN '{finding.arn}' does not start with 'arn:aws:'"
                )

    def test_fixture_provider_schema_validation_float_savings(self):
        """Test all fixture est_monthly_saved_usd are float type."""
        results = FixtureProvider.get_fixture_results()
        for result in results:
            for finding in result.findings:
                assert isinstance(finding.est_monthly_saved_usd, float), (
                    f"est_monthly_saved_usd '{finding.est_monthly_saved_usd}' is not float"
                )

    def test_fixture_provider_schema_validation_command_prefix(self):
        """Test all fixture fix_commands start with 'aws '."""
        results = FixtureProvider.get_fixture_results()
        for result in results:
            for finding in result.findings:
                assert finding.fix_command.startswith("aws "), (
                    f"fix_command '{finding.fix_command}' does not start with 'aws '"
                )

    def test_fixture_provider_exact_values_idle_ec2(self):
        """Test idle-ec2 fixture has exact values from architecture doc."""
        results = FixtureProvider.get_fixture_results()
        idle_ec2 = next(r for r in results if r.rule_id == "idle-ec2")

        assert len(idle_ec2.findings) == 1
        finding = idle_ec2.findings[0]

        assert "i-0abc123def456" in finding.arn
        assert "i-0abc123def456" in finding.finding
        assert finding.est_monthly_saved_usd == 156.00
        assert "i-0abc123def456" in finding.fix_command

    def test_fixture_provider_exact_values_oversized_rds(self):
        """Test oversized-rds fixture has exact values from architecture doc."""
        results = FixtureProvider.get_fixture_results()
        oversized_rds = next(r for r in results if r.rule_id == "oversized-rds")

        assert len(oversized_rds.findings) == 1
        finding = oversized_rds.findings[0]

        assert "mydb" in finding.arn
        assert "mydb" in finding.finding
        assert finding.est_monthly_saved_usd == 89.50
        assert "mydb" in finding.fix_command

    def test_fixture_provider_exact_values_orphan_ebs(self):
        """Test orphan-ebs fixture has exact values from architecture doc."""
        results = FixtureProvider.get_fixture_results()
        orphan_ebs = next(r for r in results if r.rule_id == "orphan-ebs")

        assert len(orphan_ebs.findings) == 1
        finding = orphan_ebs.findings[0]

        assert "vol-0xyz789" in finding.arn
        assert "vol-0xyz789" in finding.finding
        assert finding.est_monthly_saved_usd == 45.60
        assert "vol-0xyz789" in finding.fix_command

    def test_fixture_provider_exact_values_untagged_spend(self):
        """Test untagged-spend fixture has exact values from architecture doc."""
        results = FixtureProvider.get_fixture_results()
        untagged_spend = next(r for r in results if r.rule_id == "untagged-spend")

        assert len(untagged_spend.findings) == 1
        finding = untagged_spend.findings[0]

        assert "i-untagged" in finding.arn
        assert "Environment" in finding.finding
        assert "CostCenter" in finding.finding
        assert finding.est_monthly_saved_usd == 0.00
        assert "i-untagged" in finding.fix_command


class TestFixtureProviderFiltering:
    """Test FixtureProvider.get_fixture_results_for_rules() filtering."""

    def test_filter_single_rule(self):
        """Test filtering to a single rule returns only that rule."""
        results = FixtureProvider.get_fixture_results_for_rules(["idle-ec2"])
        assert len(results) == 1
        assert results[0].rule_id == "idle-ec2"

    def test_filter_two_rules(self):
        """Test filtering to two rules returns both rules."""
        results = FixtureProvider.get_fixture_results_for_rules(["idle-ec2", "orphan-ebs"])
        assert len(results) == 2
        rule_ids = {r.rule_id for r in results}
        assert rule_ids == {"idle-ec2", "orphan-ebs"}

    def test_filter_all_rules(self):
        """Test filtering to all rules returns all 4 results."""
        all_rules = ["idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"]
        results = FixtureProvider.get_fixture_results_for_rules(all_rules)
        assert len(results) == 4

    def test_filter_empty_list(self):
        """Test filtering with empty list returns empty results."""
        results = FixtureProvider.get_fixture_results_for_rules([])
        assert len(results) == 0

    def test_filter_nonexistent_rule(self):
        """Test filtering with nonexistent rule returns empty results."""
        results = FixtureProvider.get_fixture_results_for_rules(["nonexistent-rule"])
        assert len(results) == 0

    def test_filter_preserves_order(self):
        """Test filtering preserves original order."""
        # Get all results
        all_results = FixtureProvider.get_fixture_results()
        all_rule_ids = [r.rule_id for r in all_results]

        # Filter to subset
        results = FixtureProvider.get_fixture_results_for_rules(["orphan-ebs", "idle-ec2"])

        # Results should be in original order (idle-ec2 before orphan-ebs)
        result_rule_ids = [r.rule_id for r in results]

        # Verify the order matches the original list order (not the input order)
        expected_order = [rid for rid in all_rule_ids if rid in ["orphan-ebs", "idle-ec2"]]
        assert result_rule_ids == expected_order

    def test_filter_returns_list(self):
        """Test filtering returns a list."""
        results = FixtureProvider.get_fixture_results_for_rules(["idle-ec2"])
        assert isinstance(results, list)

    def test_filter_returns_rule_result_objects(self):
        """Test filtering returns RuleResult objects."""
        results = FixtureProvider.get_fixture_results_for_rules(["idle-ec2", "orphan-ebs"])
        for result in results:
            assert isinstance(result, RuleResult)


# ============================================================================
# Tests for Fixture Data Matches Architecture Doc
# ============================================================================

class TestFixtureDataMatchesArchitecture:
    """Test that fixture data matches exact values from architecture document."""

    def test_idle_ec2_instance_id(self):
        """Test idle-ec2 uses instance ID i-0abc123def456."""
        results = FixtureProvider.get_fixture_results()
        idle_ec2 = next(r for r in results if r.rule_id == "idle-ec2")
        finding = idle_ec2.findings[0]
        assert "i-0abc123def456" in finding.arn

    def test_oversized_rds_db_identifier(self):
        """Test oversized-rds uses db identifier mydb."""
        results = FixtureProvider.get_fixture_results()
        oversized_rds = next(r for r in results if r.rule_id == "oversized-rds")
        finding = oversized_rds.findings[0]
        assert "mydb" in finding.arn

    def test_orphan_ebs_volume_id(self):
        """Test orphan-ebs uses volume ID vol-0xyz789."""
        results = FixtureProvider.get_fixture_results()
        orphan_ebs = next(r for r in results if r.rule_id == "orphan-ebs")
        finding = orphan_ebs.findings[0]
        assert "vol-0xyz789" in finding.arn

    def test_untagged_spend_instance_id(self):
        """Test untagged-spend uses instance ID i-untagged."""
        results = FixtureProvider.get_fixture_results()
        untagged_spend = next(r for r in results if r.rule_id == "untagged-spend")
        finding = untagged_spend.findings[0]
        assert "i-untagged" in finding.arn


# ============================================================================
# Tests for No AWS Calls in Fixture
# ============================================================================

class TestNoAWSCalls:
    """Test that FixtureProvider makes no AWS calls."""

    def test_get_fixture_results_no_imports(self):
        """Verify get_fixture_results() doesn't import boto3."""
        # Since FixtureProvider is a static class that only returns hardcoded data,
        # we verify it works without requiring boto3 by checking:
        # 1. The recommend module doesn't import boto3 at the top level
        # 2. The function returns data correctly

        # Verify boto3 is not in the recommend module's globals
        assert 'boto3' not in recommend_module.__dict__, (
            "recommend module should not import boto3 at top level"
        )

        # Verify we can get results (no AWS dependencies)
        results = FixtureProvider.get_fixture_results()
        assert len(results) == 4, "Should return 4 results without any AWS calls"

    def test_get_fixture_results_for_rules_no_imports(self):
        """Verify get_fixture_results_for_rules() doesn't import boto3."""
        # Verify boto3 is not in the recommend module's globals
        assert 'boto3' not in recommend_module.__dict__, (
            "recommend module should not import boto3 at top level"
        )

        # Verify we can get filtered results (no AWS dependencies)
        results = FixtureProvider.get_fixture_results_for_rules(["idle-ec2"])
        assert len(results) == 1, "Should return filtered results without any AWS calls"


# ============================================================================
# Tests for ReportGenerator Class
# ============================================================================

class TestReportGenerator:
    """Test ReportGenerator class for markdown output."""

    def test_report_sorted_by_savings_descending(self):
        """Findings in report are sorted by est_monthly_saved_usd descending (highest first)."""
        generator = ReportGenerator()

        # Create findings with known savings values in mixed order
        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-low",
                        finding="Low savings finding",
                        est_monthly_saved_usd=10.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-low"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:volume/vol-high",
                        finding="High savings finding",
                        est_monthly_saved_usd=200.00,
                        fix_command="aws ec2 delete-volume --volume-id vol-high"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="oversized-rds",
                findings=[
                    Finding(
                        arn="arn:aws:rds:us-east-1:123:db:mydb",
                        finding="Medium savings finding",
                        est_monthly_saved_usd=50.00,
                        fix_command="aws rds modify-db-instance --db-instance-identifier mydb"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs", "oversized-rds"])

        # Extract savings values from report (they appear in table rows)
        import re
        savings_matches = re.findall(r'\$(\d+(?:,\d{3})*\.\d{2})', output)

        # Filter out the total row (last one) and convert to floats
        savings_in_table = []
        for match in savings_matches:
            value = float(match.replace(',', ''))
            savings_in_table.append(value)

        # The total savings is the last value; remove it
        if savings_in_table:
            # The report has findings table values followed by total
            # Total is 260.00, so findings should be before that
            findings_savings = [s for s in savings_in_table if s != 260.00]

            # Should be sorted descending: 200.00, 50.00, 10.00
            assert findings_savings == sorted(findings_savings, reverse=True), (
                f"Findings not sorted descending: {findings_savings}"
            )

    def test_report_header_includes_required_elements(self):
        """Report header includes title, timestamp, and rules executed."""
        generator = ReportGenerator()
        results = FixtureProvider.get_fixture_results()
        rules_executed = ["idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"]

        output = generator.generate(results, rules_executed)

        # Check title
        assert "# FinOps Recommendations Report" in output

        # Check timestamp format (Generated: YYYY-MM-DDTHH:MM:SSZ)
        import re
        assert re.search(r'Generated: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', output), (
            "Report should contain timestamp in ISO format"
        )

        # Check rules executed
        assert "Rules executed:" in output
        for rule in rules_executed:
            assert rule in output, f"Rule '{rule}' should be in rules executed list"

    def test_report_includes_rule_errors_section_when_errors_present(self):
        """Report includes Rule Errors section when at least one rule has error set."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[],
                error="AccessDeniedException: User not authorized"
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:volume/vol-x",
                        finding="test finding",
                        est_monthly_saved_usd=10.00,
                        fix_command="aws ec2 delete-volume --volume-id vol-x"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs"])

        # Verify Rule Errors section exists
        assert "## Rule Errors" in output
        assert "idle-ec2" in output
        assert "AccessDeniedException" in output or "User not authorized" in output

        # Verify successful findings also appear
        assert "vol-x" in output

    def test_report_no_rule_errors_section_when_all_succeed(self):
        """Report does NOT include Rule Errors section when all rules succeed."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-test",
                        finding="test finding",
                        est_monthly_saved_usd=100.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-test"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2"])

        # Rule Errors section should NOT be present
        assert "## Rule Errors" not in output

    def test_report_empty_findings_shows_message(self):
        """Report shows 'No findings' message when no findings."""
        generator = ReportGenerator()

        results = [
            RuleResult(rule_id="idle-ec2", findings=[], error=None),
            RuleResult(rule_id="orphan-ebs", findings=[], error=None),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs"])

        assert "No findings" in output

    def test_report_total_savings_calculation(self):
        """Total estimated monthly savings is correct."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-1",
                        finding="Finding 1",
                        est_monthly_saved_usd=100.50,
                        fix_command="aws ec2 stop-instances --instance-ids i-1"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:volume/vol-1",
                        finding="Finding 2",
                        est_monthly_saved_usd=50.25,
                        fix_command="aws ec2 delete-volume --volume-id vol-1"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs"])

        # Total should be 100.50 + 50.25 = 150.75
        assert "Total estimated monthly savings: $150.75" in output

    def test_report_savings_formatting_with_commas(self):
        """Savings are formatted as $X,XXX.XX with dollar sign, commas, and two decimals."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-1",
                        finding="High savings",
                        est_monthly_saved_usd=1234.56,
                        fix_command="aws ec2 stop-instances --instance-ids i-1"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2"])

        # Check formatting with dollar sign, comma, and two decimals
        assert "$1,234.56" in output

    def test_report_large_savings_formatting_with_multiple_commas(self):
        """Large savings are formatted correctly with multiple commas."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-1",
                        finding="Very high savings",
                        est_monthly_saved_usd=12345678.90,
                        fix_command="aws ec2 stop-instances --instance-ids i-1"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2"])

        # Check formatting with multiple commas
        assert "$12,345,678.90" in output

    def test_report_findings_table_has_correct_columns(self):
        """Findings table has columns: ARN, Finding, Est. Monthly Savings, Fix Command."""
        generator = ReportGenerator()
        results = FixtureProvider.get_fixture_results()

        output = generator.generate(
            results,
            ["idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"]
        )

        # Check column headers exist
        assert "| ARN |" in output
        assert "| Finding |" in output or "Finding |" in output
        assert "Est. Monthly Savings" in output
        assert "Fix Command" in output

    def test_report_rule_errors_table_shows_rule_id_and_error(self):
        """Rule Errors table shows rule_id and error message."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[],
                error="Simulated failure message"
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[],
                error="Another error occurred"
            ),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs"])

        # Check errors section exists and contains both errors
        assert "## Rule Errors" in output
        assert "idle-ec2" in output
        assert "Simulated failure message" in output
        assert "orphan-ebs" in output
        assert "Another error occurred" in output

    def test_report_excludes_findings_from_failed_rules(self):
        """Findings from rules with errors are NOT included in total savings."""
        generator = ReportGenerator()

        results = [
            # This rule has error AND findings - findings should be excluded
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-should-be-ignored",
                        finding="This should be ignored",
                        est_monthly_saved_usd=1000.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-should-be-ignored"
                    )
                ],
                error="This rule failed"  # Error is set, so findings shouldn't count
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:volume/vol-good",
                        finding="This should be included",
                        est_monthly_saved_usd=50.00,
                        fix_command="aws ec2 delete-volume --volume-id vol-good"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2", "orphan-ebs"])

        # Total should only be 50.00 (not 1050.00)
        assert "Total estimated monthly savings: $50.00" in output

    def test_report_fix_command_formatted_in_backticks(self):
        """Fix commands are wrapped in backticks in the table."""
        generator = ReportGenerator()

        results = [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123:instance/i-test",
                        finding="test",
                        est_monthly_saved_usd=100.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-test"
                    )
                ],
                error=None
            ),
        ]

        output = generator.generate(results, ["idle-ec2"])

        # Fix command should be wrapped in backticks
        assert "`aws ec2 stop-instances --instance-ids i-test`" in output
# Tests for BaseRule ABC
# ============================================================================

class TestBaseRule:
    """Test BaseRule abstract base class."""

    def test_base_rule_is_abstract(self):
        """Test that BaseRule cannot be instantiated directly."""
        from abc import ABC
        assert issubclass(BaseRule, ABC), "BaseRule should be an ABC"

    def test_base_rule_has_rule_id_property(self):
        """Test that BaseRule defines abstract rule_id property."""
        import inspect
        assert hasattr(BaseRule, 'rule_id'), "BaseRule should have rule_id property"

    def test_base_rule_has_execute_method(self):
        """Test that BaseRule defines abstract execute method."""
        import inspect
        assert hasattr(BaseRule, 'execute'), "BaseRule should have execute method"


# ============================================================================
# Tests for IdleEc2Rule
# ============================================================================

class TestIdleEc2Rule:
    """Tests for IdleEc2Rule using botocore.stub.Stubber."""

    def test_idle_ec2_rule_extends_base_rule(self):
        """Test IdleEc2Rule extends BaseRule."""
        assert issubclass(IdleEc2Rule, BaseRule), "IdleEc2Rule should extend BaseRule"

    def test_idle_ec2_rule_id(self):
        """Test IdleEc2Rule has correct rule_id."""
        rule = IdleEc2Rule()
        assert rule.rule_id == "idle-ec2", "IdleEc2Rule.rule_id should be 'idle-ec2'"

    def test_idle_ec2_detects_low_cpu_instance(self):
        """Test rule detects instance with <5% CPU (2.3% avg)."""
        import boto3
        from botocore.stub import Stubber

        rule = IdleEc2Rule()

        # Setup EC2 client and stubber
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        ec2_stubber = Stubber(ec2_client)

        # Mock DescribeInstances response with running instance
        # OwnerId is at the Reservation level, not Instance level
        ec2_stubber.add_response(
            'describe_instances',
            {
                'Reservations': [{
                    'OwnerId': '123456789012',
                    'Instances': [{
                        'InstanceId': 'i-12345678',
                        'InstanceType': 'm5.large',
                        'State': {'Name': 'running'}
                    }]
                }]
            },
            expected_params={
                'Filters': [{'Name': 'instance-state-name', 'Values': ['running']}]
            }
        )

        # Setup CloudWatch client and stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU (2.3%)
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 2.3, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        ec2_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._ec2_client = ec2_client
        rule._cw_client = cw_client

        result = rule.execute()

        ec2_stubber.deactivate()
        cw_stubber.deactivate()

        assert result.rule_id == "idle-ec2"
        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].arn.startswith("arn:aws:ec2:")
        assert "i-12345678" in result.findings[0].arn
        assert "2.3%" in result.findings[0].finding
        assert result.findings[0].est_monthly_saved_usd > 0
        assert result.findings[0].fix_command == "aws ec2 stop-instances --instance-ids i-12345678"

    def test_idle_ec2_no_findings_when_cpu_above_threshold(self):
        """Test rule returns no findings when CPU > 5%."""
        import boto3
        from botocore.stub import Stubber

        rule = IdleEc2Rule()

        # Setup EC2 client and stubber
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        ec2_stubber = Stubber(ec2_client)

        # Mock DescribeInstances response with running instance
        # OwnerId is at the Reservation level, not Instance level
        ec2_stubber.add_response(
            'describe_instances',
            {
                'Reservations': [{
                    'OwnerId': '123456789012',
                    'Instances': [{
                        'InstanceId': 'i-12345678',
                        'InstanceType': 'm5.large',
                        'State': {'Name': 'running'}
                    }]
                }]
            },
            expected_params={
                'Filters': [{'Name': 'instance-state-name', 'Values': ['running']}]
            }
        )

        # Setup CloudWatch client and stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with 10% CPU (above threshold)
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 10.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        ec2_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._ec2_client = ec2_client
        rule._cw_client = cw_client

        result = rule.execute()

        ec2_stubber.deactivate()
        cw_stubber.deactivate()

        assert result.rule_id == "idle-ec2"
        assert result.error is None
        assert len(result.findings) == 0, "No findings should be returned when CPU is above threshold"

    def test_idle_ec2_handles_no_credentials_error_gracefully(self):
        """Test rule handles NoCredentialsError gracefully."""
        import botocore.exceptions

        rule = IdleEc2Rule()

        # Create a mock that raises NoCredentialsError
        class MockEC2Client:
            def get_paginator(self, operation_name):
                raise botocore.exceptions.NoCredentialsError()

            @property
            def meta(self):
                class Meta:
                    region_name = 'us-east-1'
                return Meta()

        rule._ec2_client = MockEC2Client()

        result = rule.execute()

        assert result.rule_id == "idle-ec2"
        assert result.error is not None
        assert "credentials" in result.error.lower()
        assert len(result.findings) == 0

    def test_idle_ec2_handles_client_error_gracefully(self):
        """Test rule handles ClientError gracefully."""
        import botocore.exceptions

        rule = IdleEc2Rule()

        # Create a mock that raises ClientError
        class MockEC2Client:
            def get_paginator(self, operation_name):
                error_response = {
                    'Error': {
                        'Code': 'AccessDenied',
                        'Message': 'User not authorized'
                    }
                }
                raise botocore.exceptions.ClientError(error_response, 'DescribeInstances')

            @property
            def meta(self):
                class Meta:
                    region_name = 'us-east-1'
                return Meta()

        rule._ec2_client = MockEC2Client()

        result = rule.execute()

        assert result.rule_id == "idle-ec2"
        assert result.error is not None
        assert "AccessDenied" in result.error
        assert len(result.findings) == 0

    def test_idle_ec2_correct_arn_format(self):
        """Test rule generates correct ARN format."""
        import boto3
        from botocore.stub import Stubber

        rule = IdleEc2Rule()

        # Setup EC2 client and stubber
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        ec2_stubber = Stubber(ec2_client)

        # Mock DescribeInstances response
        # OwnerId is at the Reservation level, not Instance level
        ec2_stubber.add_response(
            'describe_instances',
            {
                'Reservations': [{
                    'OwnerId': '999888777666',
                    'Instances': [{
                        'InstanceId': 'i-abc123xyz',
                        'InstanceType': 't3.medium',
                        'State': {'Name': 'running'}
                    }]
                }]
            },
            expected_params={
                'Filters': [{'Name': 'instance-state-name', 'Values': ['running']}]
            }
        )

        # Setup CloudWatch client and stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 1.5, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        ec2_stubber.activate()
        cw_stubber.activate()

        rule._ec2_client = ec2_client
        rule._cw_client = cw_client

        result = rule.execute()

        ec2_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        arn = result.findings[0].arn
        # ARN format: arn:aws:ec2:{region}:{account_id}:instance/{instance_id}
        assert arn.startswith("arn:aws:ec2:")
        assert "us-east-1" in arn
        assert "999888777666" in arn
        assert "i-abc123xyz" in arn
        assert ":instance/" in arn

    def test_idle_ec2_correct_savings_calculation(self):
        """Test rule calculates savings correctly (hourly_rate * 730)."""
        import boto3
        from botocore.stub import Stubber

        rule = IdleEc2Rule()

        # Setup EC2 client and stubber
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        ec2_stubber = Stubber(ec2_client)

        # Mock DescribeInstances response with m5.large instance
        # OwnerId is at the Reservation level, not Instance level
        ec2_stubber.add_response(
            'describe_instances',
            {
                'Reservations': [{
                    'OwnerId': '123456789012',
                    'Instances': [{
                        'InstanceId': 'i-savings-test',
                        'InstanceType': 'm5.large',  # $0.096/hr
                        'State': {'Name': 'running'}
                    }]
                }]
            },
            expected_params={
                'Filters': [{'Name': 'instance-state-name', 'Values': ['running']}]
            }
        )

        # Setup CloudWatch client and stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 2.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        ec2_stubber.activate()
        cw_stubber.activate()

        rule._ec2_client = ec2_client
        rule._cw_client = cw_client

        result = rule.execute()

        ec2_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        # m5.large hourly rate is $0.096
        # Monthly savings = 0.096 * 730 = $70.08
        expected_savings = INSTANCE_PRICING['m5.large'] * 730
        assert result.findings[0].est_monthly_saved_usd == expected_savings


class TestIdleEc2RuleConstants:
    """Test IdleEc2Rule constants."""

    def test_cpu_threshold_is_5_percent(self):
        """Test CPU_THRESHOLD is set to 5.0."""
        assert CPU_THRESHOLD == 5.0, "CPU_THRESHOLD should be 5.0 percent"

    def test_lookback_days_is_7(self):
        """Test LOOKBACK_DAYS is set to 7."""
        assert LOOKBACK_DAYS == 7, "LOOKBACK_DAYS should be 7 days"

    def test_instance_pricing_contains_required_types(self):
        """Test INSTANCE_PRICING contains required instance types."""
        required_types = ['t2.micro', 't3.medium', 'm5.large']
        for instance_type in required_types:
            assert instance_type in INSTANCE_PRICING, (
                f"INSTANCE_PRICING should contain {instance_type}"
            )

    def test_instance_pricing_values_are_floats(self):
        """Test all INSTANCE_PRICING values are floats."""
        for instance_type, price in INSTANCE_PRICING.items():
            assert isinstance(price, float), (
                f"Price for {instance_type} should be a float"
            )

    def test_fix_command_format(self):
        """Test fix_command follows correct format."""
        import boto3
        from botocore.stub import Stubber

        rule = IdleEc2Rule()

        # Setup EC2 client and stubber
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        ec2_stubber = Stubber(ec2_client)

        # Mock DescribeInstances response
        # OwnerId is at the Reservation level, not Instance level
        ec2_stubber.add_response(
            'describe_instances',
            {
                'Reservations': [{
                    'OwnerId': '123456789012',
                    'Instances': [{
                        'InstanceId': 'i-testinstance',
                        'InstanceType': 't2.micro',
                        'State': {'Name': 'running'}
                    }]
                }]
            },
            expected_params={
                'Filters': [{'Name': 'instance-state-name', 'Values': ['running']}]
            }
        )

        # Setup CloudWatch client and stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 1.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        ec2_stubber.activate()
        cw_stubber.activate()

        rule._ec2_client = ec2_client
        rule._cw_client = cw_client

        result = rule.execute()

        ec2_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        fix_cmd = result.findings[0].fix_command
        # Verify format: aws ec2 stop-instances --instance-ids {id}
        assert fix_cmd == "aws ec2 stop-instances --instance-ids i-testinstance"
        assert fix_cmd.startswith("aws ec2 stop-instances --instance-ids ")

# ============================================================================
# Tests for OversizedRdsRule
# ============================================================================

class TestOversizedRdsRule:
    """Tests for OversizedRdsRule using botocore.stub.Stubber."""

    def test_oversized_rds_rule_id(self):
        """Test OversizedRdsRule has correct rule_id."""
        rule = OversizedRdsRule()
        assert rule.rule_id == "oversized-rds"

    def test_oversized_rds_cpu_threshold(self):
        """Test CPU_THRESHOLD constant is 30.0."""
        assert OversizedRdsRule.CPU_THRESHOLD == 30.0

    def test_oversized_rds_savings_ratio(self):
        """Test SAVINGS_RATIO constant is 0.30."""
        assert OversizedRdsRule.SAVINGS_RATIO == 0.30

    def test_oversized_rds_pricing_dict(self):
        """Test RDS_PRICING dict exists with expected instance types."""
        pricing = OversizedRdsRule.RDS_PRICING
        assert "db.t3.micro" in pricing
        assert "db.m5.large" in pricing
        assert isinstance(pricing["db.t3.micro"], float)
        assert isinstance(pricing["db.m5.large"], float)

    def test_oversized_rds_downsize_map(self):
        """Test DOWNSIZE_MAP dict exists with expected mappings."""
        downsize_map = OversizedRdsRule.DOWNSIZE_MAP
        assert "db.m5.xlarge" in downsize_map
        assert downsize_map["db.m5.xlarge"] == "db.m5.large"
        assert "db.m5.large" in downsize_map
        assert downsize_map["db.m5.large"] == "db.t3.medium"

    def test_oversized_rds_detects_low_cpu_instance(self):
        """Test rule detects RDS instance with <30% CPU (12% avg)."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'test-db',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:test-db',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU (12%)
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 12.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        assert result.rule_id == "oversized-rds"
        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].arn.startswith("arn:aws:rds:")
        assert "test-db" in result.findings[0].arn
        assert result.findings[0].est_monthly_saved_usd > 0
        assert "12.0%" in result.findings[0].finding

    def test_oversized_rds_no_findings_high_cpu(self):
        """Test rule returns no findings for instance with >30% CPU (40% avg)."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'active-db',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:active-db',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with high CPU (40%)
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 40.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        assert result.rule_id == "oversized-rds"
        assert result.error is None
        assert len(result.findings) == 0

    def test_oversized_rds_handles_errors_gracefully(self):
        """Test rule handles errors gracefully and returns RuleResult with error."""
        rule = OversizedRdsRule()

        # Setup RDS stubber with error
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Add error response
        rds_stubber.add_client_error(
            'describe_db_instances',
            service_error_code='AccessDeniedException',
            service_message='User: arn:aws:iam::123456789012:user/test is not authorized'
        )

        rds_stubber.activate()

        # Inject stubbed client
        rule._rds_client = rds_client

        result = rule.execute()

        rds_stubber.deactivate()

        assert result.rule_id == "oversized-rds"
        assert result.error is not None
        assert "AccessDeniedException" in result.error
        assert len(result.findings) == 0

    def test_oversized_rds_correct_arn_format(self):
        """Test that findings have correct ARN format arn:aws:rds:..."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response with proper ARN
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'mydb',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:mydb',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 15.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        finding = result.findings[0]
        # Verify ARN format
        assert finding.arn.startswith("arn:aws:rds:")
        assert ":db:" in finding.arn
        assert "mydb" in finding.arn

    def test_oversized_rds_fix_command_includes_smaller_class(self):
        """Test fix_command includes downsized instance class from DOWNSIZE_MAP."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response with db.m5.large (maps to db.t3.medium)
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'test-db-large',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:test-db-large',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 10.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        finding = result.findings[0]

        # Verify fix_command format and smaller class
        assert finding.fix_command.startswith("aws rds modify-db-instance")
        assert "--db-instance-identifier test-db-large" in finding.fix_command
        # db.m5.large should map to db.t3.medium per DOWNSIZE_MAP
        assert "--db-instance-class db.t3.medium" in finding.fix_command

    def test_oversized_rds_savings_calculation(self):
        """Test monthly savings calculated as current_monthly_cost * SAVINGS_RATIO."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'pricing-test-db',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:pricing-test-db',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with low CPU
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': [
                    {'Average': 5.0, 'Timestamp': datetime.now(timezone.utc)}
                ]
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        assert len(result.findings) == 1
        finding = result.findings[0]

        # db.m5.large hourly rate is 0.171
        # Monthly cost = 0.171 * 730 = 124.83
        # Expected savings = 124.83 * 0.30 = 37.449, rounded to 37.45
        expected_monthly_cost = OversizedRdsRule.RDS_PRICING["db.m5.large"] * 730
        expected_savings = round(expected_monthly_cost * OversizedRdsRule.SAVINGS_RATIO, 2)

        assert finding.est_monthly_saved_usd == expected_savings

    def test_oversized_rds_no_metrics_data(self):
        """Test rule handles instances without CloudWatch metrics gracefully."""
        rule = OversizedRdsRule()

        # Setup RDS stubber
        rds_client = boto3.client('rds', region_name='us-east-1')
        rds_stubber = Stubber(rds_client)

        # Mock DescribeDBInstances response
        rds_stubber.add_response(
            'describe_db_instances',
            {
                'DBInstances': [{
                    'DBInstanceIdentifier': 'new-db',
                    'DBInstanceClass': 'db.m5.large',
                    'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:new-db',
                    'DBInstanceStatus': 'available'
                }]
            }
        )

        # Setup CloudWatch stubber
        cw_client = boto3.client('cloudwatch', region_name='us-east-1')
        cw_stubber = Stubber(cw_client)

        # Mock GetMetricStatistics response with NO datapoints
        cw_stubber.add_response(
            'get_metric_statistics',
            {
                'Datapoints': []
            }
        )

        rds_stubber.activate()
        cw_stubber.activate()

        # Inject stubbed clients
        rule._rds_client = rds_client
        rule._cw_client = cw_client

        result = rule.execute()

        rds_stubber.deactivate()
        cw_stubber.deactivate()

        # Should skip instances without metrics data
        assert result.rule_id == "oversized-rds"
        assert result.error is None
        assert len(result.findings) == 0

    def test_oversized_rds_extends_base_rule(self):
        """Test that OversizedRdsRule extends BaseRule."""
        BaseRule = recommend_module.BaseRule
        assert issubclass(OversizedRdsRule, BaseRule)

# ============================================================================
# Tests for OrphanEbsRule
# ============================================================================

class TestOrphanEbsRule:
    """Tests for OrphanEbsRule using botocore.stub.Stubber."""

    def test_orphan_ebs_rule_id(self):
        """Test OrphanEbsRule has correct rule_id."""
        rule = OrphanEbsRule()
        assert rule.rule_id == "orphan-ebs"

    def test_orphan_ebs_extends_base_rule(self):
        """Test OrphanEbsRule extends BaseRule."""
        rule = OrphanEbsRule()
        assert isinstance(rule, BaseRule)

    def test_orphan_ebs_age_threshold(self):
        """Test AGE_THRESHOLD_DAYS is 14."""
        assert OrphanEbsRule.AGE_THRESHOLD_DAYS == 14

    def test_orphan_ebs_pricing_dict(self):
        """Test EBS_PRICING dict has required volume types."""
        expected_types = {'gp2', 'gp3', 'io1', 'io2', 'st1', 'sc1', 'standard'}
        assert set(OrphanEbsRule.EBS_PRICING.keys()) == expected_types

    def test_orphan_ebs_detects_old_unattached_volume(self):
        """Test rule detects volume unattached >14 days."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        # Volume created 21 days ago
        create_time = datetime.now(timezone.utc) - timedelta(days=21)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-12345678',
                    'VolumeType': 'gp2',
                    'Size': 100,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'us-east-1a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.rule_id == "orphan-ebs"
        assert result.error is None
        assert len(result.findings) == 1
        assert "vol-12345678" in result.findings[0].arn
        assert result.findings[0].arn.startswith("arn:aws:ec2:")
        assert "volume/vol-12345678" in result.findings[0].arn
        assert "21 days" in result.findings[0].finding
        assert result.findings[0].fix_command == "aws ec2 delete-volume --volume-id vol-12345678"

    def test_orphan_ebs_ignores_recent_volume(self):
        """Test rule ignores volume unattached <14 days (7 days old)."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        # Volume created 7 days ago (should NOT be flagged)
        create_time = datetime.now(timezone.utc) - timedelta(days=7)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-recent',
                    'VolumeType': 'gp3',
                    'Size': 50,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'us-east-1a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.rule_id == "orphan-ebs"
        assert result.error is None
        assert len(result.findings) == 0  # Should not find the recent volume

    def test_orphan_ebs_savings_calculation(self):
        """Test savings calculation uses volume size * pricing."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        # Volume: 100 GB gp2 ($0.10/GB-month) = $10.00/month
        create_time = datetime.now(timezone.utc) - timedelta(days=21)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-savings-test',
                    'VolumeType': 'gp2',
                    'Size': 100,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'us-east-1a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.error is None
        assert len(result.findings) == 1
        # 100 GB * $0.10/GB = $10.00
        assert result.findings[0].est_monthly_saved_usd == 10.0

    def test_orphan_ebs_savings_gp3_pricing(self):
        """Test savings calculation for gp3 volume type."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        # Volume: 200 GB gp3 ($0.08/GB-month) = $16.00/month
        create_time = datetime.now(timezone.utc) - timedelta(days=21)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-gp3-test',
                    'VolumeType': 'gp3',
                    'Size': 200,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'us-west-2a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.error is None
        assert len(result.findings) == 1
        # 200 GB * $0.08/GB = $16.00
        assert result.findings[0].est_monthly_saved_usd == 16.0

    def test_orphan_ebs_error_handling_client_error(self):
        """Test error handling for ClientError."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        stubber.add_client_error(
            'describe_volumes',
            service_error_code='AccessDeniedException',
            service_message='User is not authorized'
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.rule_id == "orphan-ebs"
        assert result.error is not None
        assert "AccessDeniedException" in result.error
        assert len(result.findings) == 0

    def test_orphan_ebs_no_volumes(self):
        """Test rule handles no available volumes."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': []
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.rule_id == "orphan-ebs"
        assert result.error is None
        assert len(result.findings) == 0

    def test_orphan_ebs_arn_format(self):
        """Test ARN format is arn:aws:ec2:region:account:volume/vol-xxx."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        create_time = datetime.now(timezone.utc) - timedelta(days=21)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-arn-test',
                    'VolumeType': 'gp2',
                    'Size': 50,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'eu-west-1a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.error is None
        assert len(result.findings) == 1
        arn = result.findings[0].arn
        # Verify ARN format
        assert arn.startswith("arn:aws:ec2:")
        assert ":volume/vol-arn-test" in arn
        # Should include region (eu-west-1 from eu-west-1a)
        assert "eu-west-1" in arn

    def test_orphan_ebs_fix_command_format(self):
        """Test fix_command format is 'aws ec2 delete-volume --volume-id {vol_id}'."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        create_time = datetime.now(timezone.utc) - timedelta(days=21)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [{
                    'VolumeId': 'vol-fix-cmd-test',
                    'VolumeType': 'gp2',
                    'Size': 50,
                    'State': 'available',
                    'CreateTime': create_time,
                    'AvailabilityZone': 'us-east-1a',
                    'Attachments': []
                }]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.error is None
        assert len(result.findings) == 1
        fix_cmd = result.findings[0].fix_command
        assert fix_cmd == "aws ec2 delete-volume --volume-id vol-fix-cmd-test"

    def test_orphan_ebs_multiple_volumes_mixed_ages(self):
        """Test rule only flags volumes older than 14 days when mixed ages present."""
        rule = OrphanEbsRule()

        ec2_client = boto3.client('ec2', region_name='us-east-1')
        stubber = Stubber(ec2_client)

        old_create_time = datetime.now(timezone.utc) - timedelta(days=21)
        recent_create_time = datetime.now(timezone.utc) - timedelta(days=7)

        stubber.add_response(
            'describe_volumes',
            {
                'Volumes': [
                    {
                        'VolumeId': 'vol-old',
                        'VolumeType': 'gp2',
                        'Size': 100,
                        'State': 'available',
                        'CreateTime': old_create_time,
                        'AvailabilityZone': 'us-east-1a',
                        'Attachments': []
                    },
                    {
                        'VolumeId': 'vol-recent',
                        'VolumeType': 'gp2',
                        'Size': 100,
                        'State': 'available',
                        'CreateTime': recent_create_time,
                        'AvailabilityZone': 'us-east-1a',
                        'Attachments': []
                    }
                ]
            },
            expected_params={
                'Filters': [{'Name': 'status', 'Values': ['available']}]
            }
        )

        stubber.activate()
        rule._ec2_client = ec2_client
        result = rule.execute()
        stubber.deactivate()

        assert result.error is None
        # Should only find the old volume
        assert len(result.findings) == 1
        assert "vol-old" in result.findings[0].arn
