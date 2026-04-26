#!/usr/bin/env python3
"""
AWS Cost Explorer Query CLI Skill

Wraps AWS Cost Explorer's get_cost_and_usage API with a developer-friendly CLI interface.
Provides cost data grouped by dimension (service, account, tag, linked-account) with
markdown table output, pagination support, and --dry-run mode for offline testing.
"""

import argparse
import sys
import re
from typing import List, Tuple, Dict
import boto3
import botocore.exceptions


def validate_date(date_str: str) -> str:
    """
    Validate date format YYYY-MM-DD.

    Args:
        date_str: Date string to validate.

    Returns:
        date_str if valid.

    Raises:
        argparse.ArgumentTypeError: If format is invalid.
    """
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        raise argparse.ArgumentTypeError(
            f"Invalid date format: {date_str}. Use YYYY-MM-DD."
        )
    return date_str


def validate_group_by(group_by_str: str) -> str:
    """
    Validate group-by dimension.

    Args:
        group_by_str: Group-by string (e.g., 'service', 'tag:Environment').

    Returns:
        group_by_str if valid.

    Raises:
        argparse.ArgumentTypeError: If not a valid dimension.
    """
    valid_dims = {'service', 'account', 'linked-account'}
    if group_by_str in valid_dims or group_by_str.startswith('tag:'):
        return group_by_str
    raise argparse.ArgumentTypeError(
        f"Invalid group-by: {group_by_str}. "
        f"Use one of: service, account, linked-account, or tag:<name>."
    )


class CostExplorerClient:
    """
    Wraps AWS Cost Explorer get_cost_and_usage API with pagination.

    Handles:
    - boto3 client initialization with default credential chain
    - Transparent pagination (NextPageToken loop)
    - Aggregation of multi-page results
    - Explicit error handling for NoCredentialsError and UnauthorizedOperation
    """

    def __init__(self):
        """Initialize boto3 client for Cost Explorer."""
        self.client = boto3.client('ce')

    def get_costs(
        self,
        start_date: str,
        end_date: str,
        group_by: str
    ) -> List[Tuple[str, float]]:
        """
        Retrieve cost data from AWS Cost Explorer.

        Args:
            start_date: Start date in YYYY-MM-DD format.
            end_date: End date in YYYY-MM-DD format.
            group_by: Grouping dimension:
                - 'service': Group by AWS service name (e.g., 'Amazon Elastic Compute Cloud')
                - 'account': Group by payer account (AWS account number, e.g., '123456789012')
                - 'linked-account': Group by member account in consolidated billing
                - 'tag:<name>': Group by tag key (e.g., 'tag:Environment')

        Returns:
            List of (dimension_name, cost_usd) tuples.
            dimension_name: Human-readable dimension (e.g., 'EC2', '123456789012', 'production')
            cost_usd: Float cost in USD (no currency symbol, no separator, e.g., 1234.56)

            Returns empty list if no results (e.g., tag does not exist).

        Raises:
            botocore.exceptions.NoCredentialsError: If AWS credentials not found.
            botocore.exceptions.ClientError:
                - If Error.Code == 'UnauthorizedOperation' (permission denied)
                - Caller must catch and handle
        """
        all_results = []
        next_page_token = None

        while True:
            # Build request
            request = {
                'TimePeriod': {
                    'Start': start_date,
                    'End': end_date
                },
                'Granularity': 'MONTHLY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': self._parse_group_by(group_by)
            }
            if next_page_token:
                request['NextPageToken'] = next_page_token

            # Call API (may raise NoCredentialsError or ClientError)
            response = self.client.get_cost_and_usage(**request)

            # Parse results from this page
            page_results = self._parse_response(response, group_by)
            all_results.extend(page_results)

            # Check for pagination
            next_page_token = response.get('NextPageToken')
            if not next_page_token:
                break

        return all_results

    def _parse_group_by(self, group_by: str) -> List[Dict[str, str]]:
        """
        Convert CLI group-by string to AWS Cost Explorer GroupBy format.

        Args:
            group_by: e.g., 'service', 'account', 'linked-account', 'tag:Environment'

        Returns:
            List of {Type: str, Key: str} dicts for AWS API.

        Examples:
            'service' → [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            'account' → [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]
            'linked-account' → [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]
            'tag:Environment' → [{'Type': 'TAG', 'Key': 'Environment'}]
        """
        if group_by == 'service':
            return [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        elif group_by == 'account':
            return [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]
        elif group_by == 'linked-account':
            return [{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]
        elif group_by.startswith('tag:'):
            tag_name = group_by.split(':', 1)[1]
            return [{'Type': 'TAG', 'Key': tag_name}]
        else:
            raise ValueError(f"Invalid group_by: {group_by}")

    def _parse_response(
        self,
        response: dict,
        group_by: str
    ) -> List[Tuple[str, float]]:
        """
        Extract dimension/cost pairs from Cost Explorer response.

        Args:
            response: Raw response from get_cost_and_usage API.
            group_by: Grouping dimension (for dimension name translation).

        Returns:
            List of (dimension_name, cost_usd) tuples.

        Detail:
            - ResultsByTime is a list of time periods (usually one per month in MONTHLY granularity)
            - For each time period, Groups contains the breakdown by dimension
            - Each group has Keys (list of dimension values) and Metrics (UnblendedCost)
            - Dimension names are translated:
              * 'SERVICE' → service name (e.g., 'Amazon Elastic Compute Cloud' → 'EC2')
              * 'LINKED_ACCOUNT' → account number (as-is)
              * 'TAG:<name>' → tag value (as-is)
            - Costs from all time periods are aggregated per dimension before returning
        """
        aggregated = {}  # {dimension_name: cost_sum}

        for time_period in response.get('ResultsByTime', []):
            for group in time_period.get('Groups', []):
                keys = group.get('Keys', [])
                cost_str = group.get('Metrics', {}).get('UnblendedCost', {}).get('Amount', '0')
                cost = float(cost_str)

                # Translate dimension name
                if keys:
                    raw_name = keys[0]
                    if group_by == 'service':
                        dimension_name = self._translate_service_name(raw_name)
                    else:
                        dimension_name = raw_name

                    # Aggregate
                    aggregated[dimension_name] = aggregated.get(dimension_name, 0.0) + cost

        return list(aggregated.items())

    def _translate_service_name(self, service_id: str) -> str:
        """
        Translate AWS service ID to human-readable name.

        Examples:
            'AmazonEC2' → 'EC2'
            'AmazonRDS' → 'RDS'
            'AWSLambda' → 'Lambda'
            'AmazonSimpleStorageService' → 'S3'

        This mapping is derived from Cost Explorer's actual service IDs.
        For unmapped services, return the service_id as-is.
        """
        service_map = {
            'AmazonEC2': 'EC2',
            'AmazonRDS': 'RDS',
            'AWSLambda': 'Lambda',
            'AmazonSimpleStorageService': 'S3',
            'AWSDataTransfer': 'Data Transfer',
        }
        return service_map.get(service_id, service_id)


class FixtureProvider:
    """
    Provides representative fixture data for --dry-run mode.

    Returns the same data every time for deterministic testing.
    No network calls; no boto3 required.
    """

    def __init__(self, group_by: str = "service"):
        """
        Initialize provider.

        Args:
            group_by: Grouping dimension (for filtering/formatting fixture).
        """
        self.group_by = group_by

    def get_fixture_table(self) -> str:
        """
        Return a markdown table string with fixture cost data.

        Returns:
            Markdown table as multi-line string. Table includes:
            - Header row: "| <DimensionName> | Cost USD |"
            - 4-5 data rows with realistic costs
            - Grand total row: "| TOTAL | $X,XXX.XX |"
            - Table is sorted descending by cost

        Examples (by group_by):

        group_by='service':
        | Service | Cost USD |
        |---------|----------|
        | EC2 | $1,234.56 |
        | RDS | $567.89 |
        | Lambda | $123.45 |
        | S3 | $89.10 |
        | TOTAL | $2,015.00 |

        group_by='account':
        | Account | Cost USD |
        |---------|----------|
        | 123456789012 | $1,500.00 |
        | 210987654321 | $800.00 |
        | 345678901234 | $715.00 |
        | TOTAL | $3,015.00 |

        group_by='linked-account':
        (same as 'account')

        group_by='tag:Environment':
        | Environment | Cost USD |
        |-------------|----------|
        | production | $2,000.00 |
        | staging | $500.00 |
        | development | $300.00 |
        | TOTAL | $2,800.00 |
        """
        fixtures = {
            'service': [
                ('EC2', 1234.56),
                ('RDS', 567.89),
                ('Lambda', 123.45),
                ('S3', 89.10),
            ],
            'account': [
                ('123456789012', 1500.00),
                ('210987654321', 800.00),
                ('345678901234', 715.00),
            ],
            'linked-account': [
                ('123456789012', 1500.00),
                ('210987654321', 800.00),
                ('345678901234', 715.00),
            ],
        }

        # Get fixture data for this group_by
        if self.group_by.startswith('tag:'):
            tag_name = self.group_by.split(':', 1)[1]
            dimension_name = tag_name
            data = [
                ('production', 2000.00),
                ('staging', 500.00),
                ('development', 300.00),
            ]
        else:
            dimension_name = self._get_dimension_display_name(self.group_by)
            data = fixtures.get(self.group_by, [])

        # Format and return
        return self._format_table(data, dimension_name)

    def _get_dimension_display_name(self, group_by: str) -> str:
        """Get the column header name for a dimension."""
        names = {
            'service': 'Service',
            'account': 'Account',
            'linked-account': 'Linked Account',
        }
        return names.get(group_by, group_by.title())

    def _format_table(
        self,
        data: List[Tuple[str, float]],
        dimension_name: str
    ) -> str:
        """
        Format data as markdown table.

        Args:
            data: List of (dimension_value, cost) tuples.
            dimension_name: Column header name.

        Returns:
            Markdown table as string.
        """
        # Sort by cost descending
        sorted_data = sorted(data, key=lambda x: x[1], reverse=True)

        # Calculate total
        total = sum(cost for _, cost in sorted_data)

        # Build table
        lines = [
            f"| {dimension_name} | Cost USD |",
            "|" + "-" * (len(dimension_name) + 2) + "|----------|",
        ]

        for name, cost in sorted_data:
            formatted_cost = f"${cost:,.2f}"
            lines.append(f"| {name} | {formatted_cost} |")

        # Grand total
        formatted_total = f"${total:,.2f}"
        lines.append(f"| TOTAL | {formatted_total} |")

        return "\n".join(lines)


class OutputFormatter:
    """
    Formats cost data as a markdown table.

    Handles:
    - Sorting by cost (descending)
    - Currency formatting (USD with thousands separator)
    - Grand total row
    - Special character escaping in dimension names
    """

    def format_table(
        self,
        results: List[Tuple[str, float]],
        group_by: str
    ) -> str:
        """
        Format cost results as markdown table.

        Args:
            results: List of (dimension_name, cost_usd) tuples from CostExplorerClient.
            group_by: Grouping dimension (used to determine column header name).

        Returns:
            Markdown table as multi-line string.

        Example input:
            results = [('EC2', 1234.56), ('Lambda', 12.34), ('RDS', 567.89)]
            group_by = 'service'

        Example output:
            | Service | Cost USD |
            |---------|----------|
            | EC2 | $1,234.56 |
            | RDS | $567.89 |
            | Lambda | $12.34 |
            | TOTAL | $1,814.79 |
        """
        # Sort by cost descending
        sorted_results = sorted(results, key=lambda x: x[1], reverse=True)

        # Calculate total
        total_cost = sum(cost for _, cost in sorted_results)

        # Get dimension header name
        dimension_header = self._get_dimension_header(group_by)

        # Build table
        lines = [
            f"| {dimension_header} | Cost USD |",
            "|" + "-" * (len(dimension_header) + 2) + "|----------|",
        ]

        for name, cost in sorted_results:
            # Escape special markdown characters
            safe_name = self._escape_name(name)
            formatted_cost = f"${cost:,.2f}"
            lines.append(f"| {safe_name} | {formatted_cost} |")

        # Grand total
        formatted_total = f"${total_cost:,.2f}"
        lines.append(f"| TOTAL | {formatted_total} |")

        return "\n".join(lines)

    def _get_dimension_header(self, group_by: str) -> str:
        """
        Get the markdown table column header name for a dimension.

        Args:
            group_by: Grouping dimension.

        Returns:
            Display name.
        """
        if group_by == 'service':
            return 'Service'
        elif group_by == 'account':
            return 'Account'
        elif group_by == 'linked-account':
            return 'Linked Account'
        elif group_by.startswith('tag:'):
            tag_name = group_by.split(':', 1)[1]
            return tag_name
        else:
            return group_by

    def _escape_name(self, name: str) -> str:
        """
        Escape special markdown characters in dimension names.

        Escapes:
        - '|' (table delimiter)
        - '\' (escape character)

        Args:
            name: Dimension name.

        Returns:
            Escaped name.
        """
        name = name.replace('\\', '\\\\')
        name = name.replace('|', '\\|')
        return name


def main() -> int:
    """
    Entry point for the skill CLI.

    Parses command-line arguments, validates them, and routes to either
    FixtureProvider (--dry-run) or CostExplorerClient (normal mode).

    Returns:
        0 on success (output printed to stdout)
        1 on expected error (credentials, permissions)
        2 on argument parsing error (argparse handles this)

    Raises:
        SystemExit: Only via argparse (exit code 2 for validation errors)
        Any unhandled exception: Bubbles to stderr (Phase 2 will add generic handler)
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Query AWS Cost Explorer for cost and usage data'
    )

    parser.add_argument(
        '--start',
        type=validate_date,
        required=False,
        help='Start date in YYYY-MM-DD format'
    )

    parser.add_argument(
        '--end',
        type=validate_date,
        required=False,
        help='End date in YYYY-MM-DD format'
    )

    parser.add_argument(
        '--group-by',
        type=validate_group_by,
        required=False,
        help='Grouping dimension: service, account, linked-account, or tag:<name>'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        default=False,
        help='Use fixture data instead of querying AWS (for testing)'
    )

    args = parser.parse_args()

    # Validate that --start, --end, --group-by are provided when --dry-run is not set
    if not args.dry_run:
        if not args.start or not args.end or not args.group_by:
            parser.error(
                'arguments --start, --end, and --group-by are required unless --dry-run is set'
            )

    try:
        if args.dry_run:
            # Use fixture data
            provider = FixtureProvider(args.group_by or "service")
            output = provider.get_fixture_table()
        else:
            # Query AWS Cost Explorer
            client = CostExplorerClient()
            results = client.get_costs(
                start_date=args.start,
                end_date=args.end,
                group_by=args.group_by
            )
            formatter = OutputFormatter()
            output = formatter.format_table(results, group_by=args.group_by)

        # Print output
        print(output)
        return 0

    except botocore.exceptions.NoCredentialsError:
        print('Error: AWS credentials not found. Configure credentials via AWS CLI or environment variables.')
        return 1

    except botocore.exceptions.ClientError as e:
        if e.response.get('Error', {}).get('Code') == 'UnauthorizedOperation':
            print('Error: AWS Cost Explorer API access denied. Ensure IAM permissions include ce:GetCostAndUsage.')
            return 1
        else:
            raise


if __name__ == '__main__':
    sys.exit(main())
