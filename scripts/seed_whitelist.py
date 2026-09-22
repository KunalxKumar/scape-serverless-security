"""Phase 4: Automate Whitelist Seeding.

Loads a clean CloudTrail log file (e.g., 7 days of normal activity),
evaluates each event with SCAPE, and for any event that triggers an alert
(decision != ALLOW), automatically adds it to the DynamoDB whitelist with
an expiration (e.g., 30 days).
"""

import argparse
import json
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def load_records(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("Records", [])
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported format")

def main():
    parser = argparse.ArgumentParser(description="Seed SCAPE whitelist from baseline logs.")
    parser.add_argument("--model", default=os.path.join(PROJECT_ROOT, "models", "my_engine.json"))
    parser.add_argument("--baseline-logs", required=True, help="Path to clean baseline log file.")
    parser.add_argument("--table", default=os.environ.get("WHITELIST_TABLE", "scape-whitelist"), help="DynamoDB whitelist table name.")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate without writing to DynamoDB.")
    parser.add_argument("--ttl-days", type=int, default=30, help="Days until whitelist entry expires.")
    args = parser.parse_args()

    engine = SCAPEEngine.load(args.model)
    print(f"Loaded model from {args.model}")

    if not os.path.exists(args.baseline_logs):
        print(f"ERROR: Baseline logs not found: {args.baseline_logs}")
        sys.exit(1)

    logs = load_records(args.baseline_logs)
    print(f"Loaded {len(logs)} events from baseline.")

    alerts_generated = {}
    prev_action = None
    prev_ts = None

    print("Evaluating events to seed whitelist...")
    for ev in logs:
        action = ev.get("eventName", "Unknown")
        ts_str = ev.get("eventTime", "")
        timestamp = engine._parse_time(ts_str) if ts_str else None

        result = engine.evaluate_event(prev_action, ev, prev_timestamp=prev_ts)
        
        if result["decision"] != "ALLOW":
            resource = "*"
            params = ev.get("requestParameters") or {}
            if isinstance(params, dict):
                for k in ("bucketName", "tableName", "functionName", "logGroupName"):
                    if k in params:
                        resource = str(params[k])
                        break
            
            key = f"{action}|{resource}"
            if key not in alerts_generated:
                alerts_generated[key] = {
                    "action": action,
                    "resource": resource,
                    "score": result["anomaly_score"],
                    "violations": result["violations"],
                    "count": 0
                }
            alerts_generated[key]["count"] += 1

        prev_action = action
        prev_ts = timestamp

    print(f"\nFound {len(alerts_generated)} unique action/resource pairs causing alerts.")

    if not alerts_generated:
        print("No whitelist entries needed.")
        sys.exit(0)

    for key, data in sorted(alerts_generated.items(), key=lambda x: x[1]["score"], reverse=True):
        print(f"  {key:<40} (Score: {data['score']:>5.2f}, Count: {data['count']:>3}, Violations: {','.join(data['violations'])[:30]}...)")

    if args.dry_run:
        print("\nDry run complete. No entries written to DynamoDB.")
        sys.exit(0)

    # Write to DynamoDB
    import boto3
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(args.table)

    ttl = int(time.time()) + (args.ttl_days * 86400)
    
    print(f"\nWriting to DynamoDB table '{args.table}'...")
    
    with table.batch_writer() as batch:
        for key, data in alerts_generated.items():
            batch.put_item(Item={
                "action_resource": key,
                "action": data["action"],
                "resource": data["resource"],
                "added_by": "seed_whitelist",
                "reason": "Baseline auto-seed",
                "ttl": ttl,
                "max_observed_score": str(data["score"]),
                "occurrences": data["count"]
            })
            
    print(f"Seeded {len(alerts_generated)} entries into {args.table}. Expires in {args.ttl_days} days.")

if __name__ == "__main__":
    main()
