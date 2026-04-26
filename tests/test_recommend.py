"""
Tests for finops-recommend recommend.py module.

Tests cover:
- Finding dataclass instantiation and field types
- RuleResult dataclass instantiation and field types
- FixtureProvider.get_fixture_results() returns 4 results (one per rule)
- FixtureProvider.get_fixture_results_for_rules() filters correctly
- Schema validation (ARN prefix, float savings, 'aws ' command prefix)
"""

import pytest
import sys
import os
import importlib.util


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
# Tests for BaseRule Abstract Class
# ============================================================================

class TestBaseRule:
    """Test BaseRule abstract class."""

    def test_base_rule_cannot_be_instantiated(self):
        """Test BaseRule cannot be instantiated directly."""
        BaseRule = recommend_module.BaseRule
        with pytest.raises(TypeError):
            BaseRule()

    def test_base_rule_requires_rule_id(self):
        """Test BaseRule requires rule_id property implementation."""
        BaseRule = recommend_module.BaseRule

        class IncompleteRule(BaseRule):
            def execute(self):
                return RuleResult(rule_id="test", findings=[], error=None)

        with pytest.raises(TypeError):
            IncompleteRule()

    def test_base_rule_requires_execute(self):
        """Test BaseRule requires execute method implementation."""
        BaseRule = recommend_module.BaseRule

        class IncompleteRule(BaseRule):
            @property
            def rule_id(self):
                return "test"

        with pytest.raises(TypeError):
            IncompleteRule()


# ============================================================================
# Tests for UntaggedSpendRule Class
# ============================================================================

class TestUntaggedSpendRule:
    """Test UntaggedSpendRule class using botocore.stub.Stubber for Cost Explorer."""

    def test_untagged_spend_rule_id(self):
        """Test UntaggedSpendRule has correct rule_id."""
        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()
        assert rule.rule_id == "untagged-spend"

    def test_untagged_spend_required_tags_constant(self):
        """Test REQUIRED_TAGS contains 'Environment' and 'CostCenter'."""
        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        assert "Environment" in UntaggedSpendRule.REQUIRED_TAGS
        assert "CostCenter" in UntaggedSpendRule.REQUIRED_TAGS

    def test_untagged_spend_lookback_days_constant(self):
        """Test LOOKBACK_DAYS is set to 30."""
        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        assert UntaggedSpendRule.LOOKBACK_DAYS == 30

    def test_untagged_spend_detects_missing_tags(self):
        """Test rule detects resources without required tags using Stubber."""
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timedelta, timezone

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        # Create stubbed Cost Explorer client
        ce_client = boto3.client('ce', region_name='us-east-1')
        stubber = Stubber(ce_client)

        # Calculate expected dates
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        # Mock response for Environment tag - shows untagged resources
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['Environment$'],  # Empty tag value
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '150.00',
                                    'Unit': 'USD'
                                }
                            }
                        },
                        {
                            'Keys': ['Environment$production'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '500.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'Environment'
                    }
                ]
            }
        )

        # Mock response for CostCenter tag - shows untagged resources
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['CostCenter$'],  # Empty tag value
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '200.00',
                                    'Unit': 'USD'
                                }
                            }
                        },
                        {
                            'Keys': ['CostCenter$engineering'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '300.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'CostCenter'
                    }
                ]
            }
        )

        with stubber:
            rule._ce_client = ce_client
            result = rule.execute()

        assert result.rule_id == "untagged-spend"
        assert result.error is None
        assert len(result.findings) >= 1

    def test_untagged_spend_savings_always_zero(self):
        """Test est_monthly_saved_usd is 0.00 for all findings."""
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timedelta, timezone

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        # Create stubbed Cost Explorer client
        ce_client = boto3.client('ce', region_name='us-east-1')
        stubber = Stubber(ce_client)

        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        # Mock response for Environment tag with untagged resources
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['Environment$'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '1000.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'Environment'
                    }
                ]
            }
        )

        # Mock response for CostCenter tag
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['CostCenter$'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '1000.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'CostCenter'
                    }
                ]
            }
        )

        with stubber:
            rule._ce_client = ce_client
            result = rule.execute()

        # All findings should have $0.00 savings
        for finding in result.findings:
            assert finding.est_monthly_saved_usd == 0.00

    def test_untagged_spend_fix_command_format(self):
        """Test fix_command has correct format."""
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timedelta, timezone

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        ce_client = boto3.client('ce', region_name='us-east-1')
        stubber = Stubber(ce_client)

        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        # Mock response for Environment tag
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['Environment$'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '100.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'Environment'
                    }
                ]
            }
        )

        # Mock response for CostCenter tag
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['CostCenter$'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '100.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'CostCenter'
                    }
                ]
            }
        )

        with stubber:
            rule._ce_client = ce_client
            result = rule.execute()

        # fix_command should follow the expected pattern
        for finding in result.findings:
            assert finding.fix_command.startswith("aws ec2 create-tags --resources")
            assert "Key=Environment,Value=TBD" in finding.fix_command
            assert "Key=CostCenter,Value=TBD" in finding.fix_command

    def test_untagged_spend_error_handling_no_credentials(self):
        """Test error handling when AWS credentials are missing."""
        import botocore.exceptions
        from unittest.mock import Mock, patch

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        # Mock the CE client to raise NoCredentialsError
        mock_client = Mock()
        mock_client.get_cost_and_usage.side_effect = botocore.exceptions.NoCredentialsError()
        rule._ce_client = mock_client

        result = rule.execute()

        assert result.rule_id == "untagged-spend"
        assert result.error is not None
        assert "credentials" in result.error.lower()
        assert len(result.findings) == 0

    def test_untagged_spend_error_handling_client_error(self):
        """Test error handling for AWS ClientError."""
        import botocore.exceptions
        from unittest.mock import Mock

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        # Mock the CE client to raise ClientError
        error_response = {'Error': {'Code': 'AccessDeniedException', 'Message': 'User not authorized'}}
        mock_client = Mock()
        mock_client.get_cost_and_usage.side_effect = botocore.exceptions.ClientError(
            error_response, 'GetCostAndUsage'
        )
        rule._ce_client = mock_client

        result = rule.execute()

        assert result.rule_id == "untagged-spend"
        assert result.error is not None
        assert "AccessDeniedException" in result.error
        assert len(result.findings) == 0

    def test_untagged_spend_error_handling_unexpected_exception(self):
        """Test error handling for unexpected exceptions."""
        from unittest.mock import Mock

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        # Mock the CE client to raise an unexpected exception
        mock_client = Mock()
        mock_client.get_cost_and_usage.side_effect = RuntimeError("Unexpected error")
        rule._ce_client = mock_client

        result = rule.execute()

        assert result.rule_id == "untagged-spend"
        assert result.error is not None
        assert "Unexpected error" in result.error
        assert len(result.findings) == 0

    def test_untagged_spend_no_untagged_resources(self):
        """Test rule returns empty findings when all resources are properly tagged."""
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timedelta, timezone

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        ce_client = boto3.client('ce', region_name='us-east-1')
        stubber = Stubber(ce_client)

        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        # Mock response for Environment tag - all resources tagged
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['Environment$production'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '500.00',
                                    'Unit': 'USD'
                                }
                            }
                        },
                        {
                            'Keys': ['Environment$development'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '200.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'Environment'
                    }
                ]
            }
        )

        # Mock response for CostCenter tag - all resources tagged
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [
                        {
                            'Keys': ['CostCenter$engineering'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '500.00',
                                    'Unit': 'USD'
                                }
                            }
                        },
                        {
                            'Keys': ['CostCenter$marketing'],
                            'Metrics': {
                                'UnblendedCost': {
                                    'Amount': '200.00',
                                    'Unit': 'USD'
                                }
                            }
                        }
                    ],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',
                        'Key': 'CostCenter'
                    }
                ]
            }
        )

        with stubber:
            rule._ce_client = ce_client
            result = rule.execute()

        assert result.rule_id == "untagged-spend"
        assert result.error is None
        assert len(result.findings) == 0

    def test_untagged_spend_extends_base_rule(self):
        """Test UntaggedSpendRule extends BaseRule."""
        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        BaseRule = recommend_module.BaseRule
        rule = UntaggedSpendRule()
        assert isinstance(rule, BaseRule)

    def test_untagged_spend_groupby_uses_tag_type(self):
        """Test that GroupBy uses TAG type for required tags."""
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timedelta, timezone

        UntaggedSpendRule = recommend_module.UntaggedSpendRule
        rule = UntaggedSpendRule()

        ce_client = boto3.client('ce', region_name='us-east-1')
        stubber = Stubber(ce_client)

        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        # Add response for Environment tag - verifying GroupBy Type is TAG
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',  # Verifying TAG type is used
                        'Key': 'Environment'
                    }
                ]
            }
        )

        # Add response for CostCenter tag - verifying GroupBy Type is TAG
        stubber.add_response(
            'get_cost_and_usage',
            {
                'ResultsByTime': [{
                    'TimePeriod': {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    'Groups': [],
                    'Estimated': False
                }]
            },
            expected_params={
                'TimePeriod': {
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [
                    {
                        'Type': 'TAG',  # Verifying TAG type is used
                        'Key': 'CostCenter'
                    }
                ]
            }
        )

        with stubber:
            rule._ce_client = ce_client
            result = rule.execute()

        # If we got here without StubResponseError, the GroupBy params matched
        assert result.error is None
