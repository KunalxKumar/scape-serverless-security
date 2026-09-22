"""Shared utilities for the SCAPE flAWS pipeline.

Provides CSV-\u003eCloudTrail conversion, session grouping,
and SCAPE engine loading without external ML dependencies.
"""

import csv
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DATASET_PATH = os.path.join(
    os.path.expanduser("~"),
    ".cache", "kagglehub", "datasets", "nobukim",
    "aws-cloudtrails-dataset-from-flaws-cloud", "versions", "1",
    "nineteenFeaturesDf.csv",
)

CSV_COLUMNS = [
    "eventID", "eventTime", "sourceIPAddress", "userAgent",
    "eventName", "eventSource", "awsRegion", "eventVersion",
    "userIdentitytype", "eventType", "requestID",
    "userIdentityaccountId", "userIdentityprincipalId",
    "userIdentityarn", "userIdentityaccessKeyId",
    "userIdentityuserName", "errorCode", "errorMessage",
    "requestParametersinstanceType",
]


# ---------------------------------------------------------------------------
# CSV -> CloudTrail event dict
# ---------------------------------------------------------------------------
def csv_row_to_event(row: Dict[str, str]) -> Dict[str, Any]:
    """Convert a flAWS CSV row into a CloudTrail-style event dict.

    The SCAPE engine expects standard CloudTrail JSON structure.
    This function maps the flat CSV columns back into that shape.
    """
    principal_id = row.get("userIdentityprincipalId", "") or ""
    arn = row.get("userIdentityarn", "") or ""
    access_key = row.get("userIdentityaccessKeyId", "") or ""
    user_name = row.get("userIdentityuserName", "") or ""

    # Build session_id: prefer ARN, fallback to principalId
    session_id = arn if arn else (principal_id if principal_id else "unknown")

    # Build resource ARN from eventSource (best available in this CSV)
    event_source = row.get("eventSource", "") or ""
    action = row.get("eventName", "Unknown") or "Unknown"

    # Approximate resource from eventSource
    resource = f"arn:aws:{event_source.replace('.amazonaws.com', '')}:::*"

    event = {
        "eventName": action,
        "eventSource": event_source,
        "eventTime": row.get("eventTime", ""),
        "awsRegion": row.get("awsRegion", "us-east-1"),
        "sourceIPAddress": row.get("sourceIPAddress", ""),
        "userAgent": row.get("userAgent", ""),
        "eventType": row.get("eventType", "AwsApiCall"),
        "errorCode": row.get("errorCode", ""),
        "errorMessage": row.get("errorMessage", ""),
        "sessionId": session_id,
        "userIdentity": {
            "type": row.get("userIdentitytype", ""),
            "principalId": principal_id,
            "arn": arn,
            "accountId": row.get("userIdentityaccountId", ""),
            "accessKeyId": access_key,
            "userName": user_name,
        },
        "requestParameters": {},
    }

    # Try to extract resource info from action name
    if "Bucket" in action or "s3" in event_source:
        event["requestParameters"]["bucketName"] = "flaws.cloud"
    elif "iam" in event_source and "Role" in action:
        event["requestParameters"]["roleName"] = "unknown-role"

    return event


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_flaws_csv(path: Optional[str] = None,
                   max_rows: Optional[int] = None) -> List[Dict[str, Any]]:
    """Load the flAWS CloudTrail CSV and convert to event dicts.

    Args:
        path: Path to CSV file (defaults to kagglehub cache location).
        max_rows: Maximum rows to load (None = all).

    Returns:
        List of CloudTrail-style event dicts.
    """
    if path is None:
        path = DATASET_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found at {path}. "
            "Run: python -c \"import kagglehub; "
            "kagglehub.dataset_download('nobukim/aws-cloudtrails-dataset-from-flaws-cloud')\""
        )

    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_rows is not None and i >= max_rows:
                break
            events.append(csv_row_to_event(row))

    return events


# ---------------------------------------------------------------------------
# Session grouping
# ---------------------------------------------------------------------------
def group_by_session(events: List[Dict]) -> Dict[str, List[Dict]]:
    """Group events by session_id and sort each session by timestamp."""
    sessions: Dict[str, List[Dict]] = defaultdict(list)
    for ev in events:
        sid = ev.get("sessionId", "unknown")
        sessions[sid].append(ev)

    # Sort each session chronologically
    for sid in sessions:
        sessions[sid].sort(key=lambda e: e.get("eventTime", ""))

    return dict(sessions)


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------
def compute_stats(events: List[Dict]) -> Dict[str, Any]:
    """Compute basic statistics about the dataset."""
    actions = defaultdict(int)
    sources = defaultdict(int)
    sessions = set()
    error_count = 0

    for ev in events:
        actions[ev.get("eventName", "Unknown")] += 1
        sources[ev.get("eventSource", "Unknown")] += 1
        sessions.add(ev.get("sessionId", "unknown"))
        if ev.get("errorCode"):
            error_count += 1

    return {
        "total_events": len(events),
        "unique_actions": len(actions),
        "unique_sessions": len(sessions),
        "unique_sources": len(sources),
        "error_events": error_count,
        "top_actions": sorted(actions.items(), key=lambda x: -x[1])[:20],
        "top_sources": sorted(sources.items(), key=lambda x: -x[1])[:10],
    }


# ---------------------------------------------------------------------------
# Printing helpers
# ---------------------------------------------------------------------------
def print_header(title: str):
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_table(headers: List[str], rows: List[List], widths: Optional[List[int]] = None):
    if widths is None:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("-" * sum(widths) + "-" * (2 * (len(widths) - 1)))
    for row in rows:
        print(fmt.format(*[str(v)[:w] for v, w in zip(row, widths)]))
