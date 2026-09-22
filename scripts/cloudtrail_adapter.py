"""Convert AWS CloudTrail JSON logs into SCAPE-compatible event JSON.

This adapter supports CloudTrail records under a top-level Records array as well
as raw event arrays. It normalizes fields so SCAPE can train on eventName,
eventTime, sessionId, requestParameters, and additionalEventData.

Usage:
    python scripts/cloudtrail_adapter.py input.json output.json [--limit N]

If the output file is omitted, the script writes to the same directory with
"_scape.json" appended to the base name.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCAPE_KEYS = [
    "eventName",
    "eventTime",
    "sessionId",
    "requestParameters",
    "additionalEventData",
    "sourceIPAddress",
    "userAgent",
    "recipientAccountId",
]


def _normalize_session_id(record: Dict[str, Any], index: int) -> str:
    # Prefer a stable identity field when available.
    user = record.get("userIdentity", {}) or {}
    principal = user.get("principalId") or user.get("arn") or user.get("accountId")
    if principal:
        return str(principal)

    session_context = record.get("sessionContext", {}) or {}
    session_issuer = session_context.get("sessionIssuer", {}) or {}
    if session_issuer.get("userName"):
        return str(session_issuer["userName"])

    # Fallback to IP address or a synthetic session id.
    source_ip = record.get("sourceIPAddress")
    if source_ip:
        return str(source_ip)

    return f"session-{index}"


def _extract_scape_fields(record: Dict[str, Any], index: int) -> Dict[str, Any]:
    data = {}
    data["eventName"] = record.get("eventName") or record.get("eventName") or "Unknown"
    data["eventTime"] = record.get("eventTime") or record.get("eventTimeStamp") or ""
    data["sessionId"] = record.get("sessionId") or _normalize_session_id(record, index)
    data["requestParameters"] = record.get("requestParameters") or {}
    data["additionalEventData"] = record.get("additionalEventData") or {}
    data["sourceIPAddress"] = record.get("sourceIPAddress")
    data["userAgent"] = record.get("userAgent")
    data["recipientAccountId"] = record.get("recipientAccountId") or record.get("accountId")

    # Normalize common resource shapes from CloudTrail metadata.
    if not data["requestParameters"]:
        request_parameters = {}
        if "bucketName" in record:
            request_parameters["bucketName"] = record["bucketName"]
        if "tableName" in record:
            request_parameters["tableName"] = record["tableName"]
        if "logGroupName" in record:
            request_parameters["logGroupName"] = record["logGroupName"]
        if "functionName" in record:
            request_parameters["functionName"] = record["functionName"]
        if "roleArn" in record:
            request_parameters["roleArn"] = record["roleArn"]
        if "queueUrl" in record:
            request_parameters["queueUrl"] = record["queueUrl"]
        if "secretId" in record:
            request_parameters["secretId"] = record["secretId"]
        if "keyId" in record:
            request_parameters["keyId"] = record["keyId"]
        if request_parameters:
            data["requestParameters"] = request_parameters

    return data


def _load_events(filepath: str) -> List[Dict[str, Any]]:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        records = data.get("Records") or data.get("events") or []
        if isinstance(records, list):
            return records
        raise ValueError("Top-level JSON object must contain a Records or events array.")
    if isinstance(data, list):
        return data
    raise ValueError("Input JSON must be an object or a list of CloudTrail records.")


def convert_cloudtrail_to_scape(input_path: str, output_path: str, limit: Optional[int] = None) -> None:
    events = _load_events(input_path)
    if limit is not None and limit > 0:
        events = events[:limit]

    normalized = []
    for index, event in enumerate(events):
        normalized.append(_extract_scape_fields(event, index))

    output = {"Records": normalized}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Converted {len(normalized)} events from {input_path} into {output_path}")


def _default_output_path(input_path: str) -> str:
    base, _ = os.path.splitext(os.path.basename(input_path))
    return os.path.join(os.path.dirname(input_path), f"{base}_scape.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert AWS CloudTrail logs into SCAPE JSON format.")
    parser.add_argument("input", help="Path to CloudTrail JSON input file")
    parser.add_argument("output", nargs="?", help="Path to write SCAPE-compatible JSON output")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of records to convert")

    args = parser.parse_args()
    output = args.output or _default_output_path(args.input)
    convert_cloudtrail_to_scape(args.input, output, args.limit)


if __name__ == "__main__":
    main()
