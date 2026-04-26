#!/usr/bin/env python3
"""
FinOps Recommend Skill

Scans AWS accounts for cost optimization opportunities across 4 rule categories,
returning findings as a markdown report sorted by estimated monthly savings.

This module provides:
- Finding: Dataclass representing a single cost optimization finding
- RuleResult: Dataclass representing results from a single rule execution
- FixtureProvider: Static class providing deterministic fixture data for --dry-run mode
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Finding:
    """Single cost optimization finding.

    Attributes:
        arn: Full AWS ARN (must start with "arn:aws:")
        finding: Human-readable description of the waste
        est_monthly_saved_usd: Estimated monthly savings in USD (>= 0.0)
        fix_command: AWS CLI command to remediate (must start with "aws ")

    Invariants:
        - arn.startswith("arn:aws:")
        - est_monthly_saved_usd >= 0.0
        - fix_command.startswith("aws ")
    """
    arn: str
    finding: str
    est_monthly_saved_usd: float
    fix_command: str


@dataclass
class RuleResult:
    """Result from a single rule execution.

    Attributes:
        rule_id: One of: "idle-ec2", "oversized-rds", "orphan-ebs", "untagged-spend"
        findings: List of Finding objects (may be empty if no issues found)
        error: None if successful, error message string if rule failed

    Usage:
        - On success: RuleResult(rule_id="idle-ec2", findings=[...], error=None)
        - On failure: RuleResult(rule_id="idle-ec2", findings=[], error="AccessDenied...")
    """
    rule_id: str
    findings: List[Finding]
    error: Optional[str]


class FixtureProvider:
    """Provides deterministic fixture data for --dry-run mode.

    No AWS calls. Returns hardcoded RuleResult objects that exercise
    all report formatting logic.
    """

    @staticmethod
    def get_fixture_results() -> List[RuleResult]:
        """Return fixture RuleResult objects for all rules.

        Returns:
            List of 4 RuleResult objects (one per rule), containing
            representative findings that validate report generation.

        Fixture Data:
            - idle-ec2: 1 finding ($156.00 savings)
            - oversized-rds: 1 finding ($89.50 savings)
            - orphan-ebs: 1 finding ($45.60 savings)
            - untagged-spend: 1 finding ($0.00 savings, tag compliance)
        """
        return [
            RuleResult(
                rule_id="idle-ec2",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
                        finding="EC2 instance i-0abc123def456 has 2.3% avg CPU over 7d",
                        est_monthly_saved_usd=156.00,
                        fix_command="aws ec2 stop-instances --instance-ids i-0abc123def456"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="oversized-rds",
                findings=[
                    Finding(
                        arn="arn:aws:rds:us-east-1:123456789012:db:mydb",
                        finding="RDS instance mydb using 12% of provisioned capacity over 7d",
                        est_monthly_saved_usd=89.50,
                        fix_command="aws rds modify-db-instance --db-instance-identifier mydb --db-instance-class db.t3.medium"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="orphan-ebs",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:volume/vol-0xyz789",
                        finding="EBS volume vol-0xyz789 unattached for 21 days",
                        est_monthly_saved_usd=45.60,
                        fix_command="aws ec2 delete-volume --volume-id vol-0xyz789"
                    )
                ],
                error=None
            ),
            RuleResult(
                rule_id="untagged-spend",
                findings=[
                    Finding(
                        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-untagged",
                        finding="Resources missing required tags: Environment, CostCenter",
                        est_monthly_saved_usd=0.00,
                        fix_command="aws ec2 create-tags --resources i-untagged --tags Key=Environment,Value=TBD Key=CostCenter,Value=TBD"
                    )
                ],
                error=None
            )
        ]

    @staticmethod
    def get_fixture_results_for_rules(rule_ids: List[str]) -> List[RuleResult]:
        """Return fixture results filtered to specified rules.

        Args:
            rule_ids: List of rule IDs to include (e.g., ["idle-ec2", "orphan-ebs"])

        Returns:
            List of RuleResult objects for specified rules only
        """
        all_results = FixtureProvider.get_fixture_results()
        return [r for r in all_results if r.rule_id in rule_ids]


class ReportGenerator:
    """Generates markdown report from rule results.

    Output Format:
        # FinOps Recommendations Report

        Generated: {timestamp}
        Rules executed: {rule_list}

        ## Findings (sorted by estimated savings)

        | ARN | Finding | Est. Monthly Savings | Fix Command |
        |-----|---------|---------------------|-------------|
        | ... | ...     | $XXX.XX             | `aws ...`   |

        ## Rule Errors (if any)

        | Rule | Error |
        |------|-------|
        | ...  | ...   |

        Total estimated monthly savings: $X,XXX.XX
    """

    def generate(self, results: List[RuleResult], executed_rules: List[str]) -> str:
        """Generate markdown report from results.

        Args:
            results: List of RuleResult objects from rule execution
            executed_rules: List of rule IDs that were executed

        Returns:
            Complete markdown report as string

        Behavior:
            - Findings sorted by est_monthly_saved_usd descending
            - Rule errors collected in separate section
            - Total savings calculated from all successful findings
            - Empty findings section shows "No findings" message
        """
        from datetime import datetime, timezone

        # Collect all findings from all results
        all_findings: List[Finding] = []
        for result in results:
            if result.error is None:
                all_findings.extend(result.findings)

        # Sort findings by est_monthly_saved_usd descending
        sorted_findings = sorted(
            all_findings,
            key=lambda f: f.est_monthly_saved_usd,
            reverse=True
        )

        # Build report sections
        lines = []

        # Header
        lines.append("# FinOps Recommendations Report")
        lines.append("")

        # Timestamp and rules executed
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        lines.append(f"Generated: {timestamp}")
        lines.append(f"Rules executed: {', '.join(executed_rules)}")
        lines.append("")

        # Findings section
        lines.append("## Findings (sorted by estimated savings)")
        lines.append("")
        lines.append(self._format_findings_table(sorted_findings))
        lines.append("")

        # Rule Errors section (only if there are errors)
        errors_section = self._format_errors_section(results)
        if errors_section:
            lines.append(errors_section)
            lines.append("")

        # Total savings
        total_savings = self._calculate_total_savings(results)
        lines.append(f"Total estimated monthly savings: ${total_savings:,.2f}")

        return '\n'.join(lines)

    def _format_findings_table(self, findings: List[Finding]) -> str:
        """Format findings as markdown table, sorted by savings descending."""
        if not findings:
            return "No findings"

        lines = []
        lines.append("| ARN | Finding | Est. Monthly Savings | Fix Command |")
        lines.append("|-----|---------|---------------------|-------------|")

        for finding in findings:
            # Format savings with dollar sign, commas, and two decimals
            savings_formatted = f"${finding.est_monthly_saved_usd:,.2f}"
            # Wrap fix_command in backticks
            fix_command_formatted = f"`{finding.fix_command}`"
            lines.append(
                f"| {finding.arn} | {finding.finding} | {savings_formatted} | {fix_command_formatted} |"
            )

        return '\n'.join(lines)

    def _format_errors_section(self, results: List[RuleResult]) -> str:
        """Format rule errors as markdown table. Returns empty string if no errors."""
        errors = [(r.rule_id, r.error) for r in results if r.error is not None]

        if not errors:
            return ""

        lines = []
        lines.append("## Rule Errors")
        lines.append("")
        lines.append("| Rule | Error |")
        lines.append("|------|-------|")

        for rule_id, error in errors:
            lines.append(f"| {rule_id} | {error} |")

        return '\n'.join(lines)

    def _calculate_total_savings(self, results: List[RuleResult]) -> float:
        """Sum est_monthly_saved_usd from all successful findings."""
        total = 0.0
        for result in results:
            if result.error is None:
                for finding in result.findings:
                    total += finding.est_monthly_saved_usd
        return total
