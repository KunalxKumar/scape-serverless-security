"""Fetch CloudTrail events using boto3 and save them as JSON."""

import argparse
import json
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def fetch_cloudtrail_events(max_events: int = 50000, region_name: Optional[str] = None) -> List[Dict[str, Any]]:
    session = boto3.Session(region_name=region_name)
    client = session.client("cloudtrail")

    records: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    remaining = max_events

    while remaining > 0:
        page_size = min(50, remaining)
        kwargs = {"MaxResults": page_size}
        if next_token:
            kwargs["NextToken"] = next_token

        response = client.lookup_events(**kwargs)
        events = response.get("Events", [])

        for ev in events:
            raw_event = ev.get("CloudTrailEvent")
            if raw_event:
                try:
                    records.append(json.loads(raw_event))
                except json.JSONDecodeError:
                    # fallback to raw event dictionary if parsing fails
                    event_copy = dict(ev)
                    event_copy["CloudTrailEvent"] = raw_event
                    records.append(event_copy)
            else:
                records.append(ev)

        remaining -= len(events)
        next_token = response.get("NextToken")
        if not next_token or not events:
            break

    return records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch CloudTrail events using boto3 and save them to JSON.")
    parser.add_argument("--max-events", type=int, default=50000, help="Maximum number of events to fetch.")
    parser.add_argument("--region", default=None, help="AWS region for the CloudTrail client. Defaults to AWS SDK settings.")
    parser.add_argument("--output", default="data/logs/my_cloudtrail_raw.json", help="Output path for the JSON file.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", args.output))
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        records = fetch_cloudtrail_events(max_events=args.max_events, region_name=args.region)
    except (BotoCoreError, ClientError) as exc:
        print(f"Failed to fetch CloudTrail events: {exc}")
        raise SystemExit(1)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"Records": records}, f, indent=2)

    print(f"Saved {len(records)} CloudTrail event records to {output_path}")


if __name__ == "__main__":
    main()
