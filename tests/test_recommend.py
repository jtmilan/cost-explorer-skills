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
# Tests for OrphanEbsRule
# ============================================================================

from datetime import datetime, timezone, timedelta
from botocore.stub import Stubber
import boto3

# Import OrphanEbsRule from the recommend module
OrphanEbsRule = recommend_module.OrphanEbsRule
BaseRule = recommend_module.BaseRule


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
