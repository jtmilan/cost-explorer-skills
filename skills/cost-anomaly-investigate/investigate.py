#!/usr/bin/env python3
"""
AWS Cost Anomaly Investigation Skill

Investigates the root causes of AWS cost spikes by correlating cost data
from Phase 1 (cost-explorer-query) with CloudWatch metrics and CloudTrail
events. Outputs a structured markdown report with spike size, likely causes,
and supporting evidence.

Module-Level Constants:
- SERVICE_TO_NAMESPACE: Maps AWS service names to CloudWatch namespaces
- SERVICE_TO_METRICS: Maps services to relevant CloudWatch metrics
- SERVICE_TO_RESOURCE_TYPE: Maps services to CloudTrail ResourceType strings
- CAUSE_DETECTION_THRESHOLDS: Heuristic thresholds for cause detection
- KNOWN_SERVICES: Set of valid service names (derived from SERVICE_TO_NAMESPACE)
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime, timezone, timedelta
import argparse
import sys
import re
import boto3
import botocore.exceptions


# ============================================================================
# Module-Level Constants
# ============================================================================

# Service-to-CloudWatch-Namespace mapping.
# Maps AWS service names (as entered via --service) to CloudWatch namespaces
# for metric retrieval.
#
# NOTE: Service names match Phase 1 query.py's service translation:
# - Phase 1 translates 'AmazonEC2' → 'EC2', 'AmazonRDS' → 'RDS', etc.
# - This mapping uses the TRANSLATED names, which align with investigate.py's
#   --service argument.
#
# INVARIANT: Every key in this dict must exist in both SERVICE_TO_METRICS
# and SERVICE_TO_RESOURCE_TYPE (enforced by unit tests).
SERVICE_TO_NAMESPACE: Dict[str, str] = {
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
    # NOTE: AppFlow, Glue, and Batch REMOVED
    #       These services exist in Phase 1's cost data but lack:
    #       (a) Meaningful CloudWatch metrics suitable for cost spike investigation
    #       (b) Clear CloudTrail ResourceType mappings
    #       If needed in future, add corresponding entries to SERVICE_TO_METRICS
    #       and SERVICE_TO_RESOURCE_TYPE.
}

# Service-to-CloudWatch-Metrics mapping.
# For each service, lists the most relevant CloudWatch metrics to fetch.
# Metrics are service-level aggregations (not per-resource; pagination
# handled automatically).
#
# INVARIANT: All 12 services from SERVICE_TO_NAMESPACE must have entries here
# with non-empty metric lists.
SERVICE_TO_METRICS: Dict[str, List[str]] = {
    'EC2': ['CPUUtilization', 'NetworkIn', 'NetworkOut'],
    'RDS': ['DatabaseConnections', 'CPUUtilization', 'ReadIOPS', 'WriteIOPS'],
    'Lambda': ['Invocations', 'Errors', 'Duration', 'ConcurrentExecutions'],
    'S3': ['NumberOfObjects', 'BucketSizeBytes'],
    'DynamoDB': ['ConsumedReadCapacityUnits', 'ConsumedWriteCapacityUnits', 'UserErrors'],
    'CloudFront': ['Requests', 'BytesDownloaded', 'BytesUploaded'],
    'ElasticSearch': ['IndexingRate', 'SearchRate', 'CPUUtilization'],
    'Kinesis': ['GetRecords.IteratorAgeMilliseconds', 'ReadProvisionedThroughputExceeded'],
    'SNS': ['MessagePublished', 'NumberOfMessagesPublished'],
    'SQS': ['ApproximateNumberOfMessagesVisible', 'NumberOfSentMessages'],
    'ECS': ['MemoryUtilization', 'CPUUtilization'],
    'EKS': ['node_cpu_utilization', 'node_memory_utilization'],
}

# Service-to-CloudTrail-ResourceType mapping.
# Maps service names to CloudTrail ResourceType for filtering events.
# ResourceType values are AWS CloudTrail's official resource type strings
# (case-sensitive).
#
# INVARIANT: All 12 services from SERVICE_TO_NAMESPACE must have entries here.
SERVICE_TO_RESOURCE_TYPE: Dict[str, str] = {
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

# Cause detection thresholds (tunable constants).
# These thresholds drive the heuristic rules in cause detection.
# Each threshold is documented with its use case.
#
# - MIN_INSTANCE_LAUNCH_COUNT: If RunInstances event count >= this value,
#   flag as spike cause
# - MIN_TOTAL_EVENTS: If total mutating events >= this value, flag as
#   high activity
# - MIN_NETWORK_SPIKE_MBPS: If NetworkIn/Out spike >= this value in Mbps,
#   flag as anomaly
CAUSE_DETECTION_THRESHOLDS: Dict[str, int] = {
    'MIN_INSTANCE_LAUNCH_COUNT': 10,
    'MIN_TOTAL_EVENTS': 20,
    'MIN_NETWORK_SPIKE_MBPS': 50,
}

# Set of known AWS services (validated against --service argument).
# Derived from SERVICE_TO_NAMESPACE keys (source of truth).
#
# INVARIANT: Every key in SERVICE_TO_NAMESPACE must exist in both
# SERVICE_TO_METRICS and SERVICE_TO_RESOURCE_TYPE. This invariant is
# enforced by unit tests (test_constants_consistency).
KNOWN_SERVICES: Set[str] = set(SERVICE_TO_NAMESPACE.keys())
