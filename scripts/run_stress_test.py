#!/usr/bin/env python3
"""Stress/Scalability Test for SCAPEEngine.

Generates 10 million synthetic CloudTrail events (99.9% normal, 0.1% attack)
and measures:
  - Throughput (events/second)
  - Memory usage (RSS in MB)
  - P99 latency per event (milliseconds)

Expected results for production-ready SCAPE:
  - Throughput: ≥50,000 events/second
  - Memory: <1 GB for 10M events
  - P99 latency: <0.1ms per event
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Installing psutil for memory monitoring...")
    os.system("pip install psutil")
    import psutil

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scape_engine import SCAPEEngine


def generate_normal_event(base_time: datetime, session_id: str, 
                          event_num: int) -> dict:
    """Generate a realistic normal CloudTrail event."""
    actions = ["s3:GetObject", "s3:PutObject", "dynamodb:Query", 
               "dynamodb:GetItem", "lambda:Invoke", "logs:PutLogEvents",
               "iam:GetUser", "sts:AssumeRole", "kms:Decrypt", "ec2:DescribeInstances"]
    resources = [
        "arn:aws:s3:::prod-bucket",
        "arn:aws:s3:::logs-bucket",
        "arn:aws:dynamodb:us-east-1:123456789012:table/users",
        "arn:aws:dynamodb:us-east-1:123456789012:table/sessions",
        "arn:aws:lambda:us-east-1:123456789012:function:processor",
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/processor",
    ]
    
    action = random.choice(actions)
    resource = random.choice(resources)
    
    event = {
        "eventName": action,
        "eventTime": (base_time + timedelta(seconds=event_num)).isoformat() + "Z",
        "sessionId": session_id,
        "requestParameters": {},
        "additionalEventData": {"bytesTransferredOut": random.randint(100, 100000)},
        "userIdentity": {"accountId": "123456789012"},
    }
    
    if "s3" in resource:
        event["requestParameters"]["bucketName"] = resource.split(":")[-1]
    elif "dynamodb" in resource:
        event["requestParameters"]["tableName"] = resource.split("/")[-1]
    
    return event


def generate_attack_event(base_time: datetime, session_id: str,
                          event_num: int, attack_type: str = "rare_action") -> dict:
    """Generate an anomalous attack event."""
    if attack_type == "rapid_burst":
        return {
            "eventName": random.choice(["s3:DeleteBucket", "iam:CreateUser", "iam:PutRolePolicy"]),
            "eventTime": (base_time + timedelta(seconds=event_num, milliseconds=1)).isoformat() + "Z",
            "sessionId": session_id,
            "requestParameters": {},
            "userIdentity": {"accountId": "123456789012"},
        }
    elif attack_type == "unseen_resource":
        return {
            "eventName": "s3:PutObject",
            "eventTime": (base_time + timedelta(seconds=event_num)).isoformat() + "Z",
            "sessionId": session_id,
            "requestParameters": {"bucketName": "evil-exfil-bucket-" + str(random.randint(0, 1000000))},
            "additionalEventData": {"bytesTransferredOut": random.randint(1000000, 10000000)},
            "userIdentity": {"accountId": "123456789012"},
        }
    else:  # cross_domain
        return {
            "eventName": "iam:CreateAccessKey",
            "eventTime": (base_time + timedelta(seconds=event_num)).isoformat() + "Z",
            "sessionId": session_id,
            "requestParameters": {},
            "userIdentity": {"accountId": "123456789012"},
        }


def generate_synthetic_dataset(num_events: int = 10_000_000,
                               attack_ratio: float = 0.001) -> list:
    """Generate synthetic CloudTrail dataset.
    
    Args:
        num_events: Total number of events to generate.
        attack_ratio: Fraction of events that are attacks (default 0.1%).
    
    Returns:
        List of CloudTrail event dicts.
    """
    events = []
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    num_sessions = max(100, num_events // 1000)  # ~1k events per session
    num_attacks = int(num_events * attack_ratio)
    attack_indices = set(random.sample(range(num_events), num_attacks))
    
    for i in range(num_events):
        session_id = f"session-{random.randint(0, num_sessions - 1)}"
        
        if i in attack_indices:
            attack_type = random.choice(["rapid_burst", "unseen_resource", "cross_domain"])
            event = generate_attack_event(base_time, session_id, i, attack_type)
        else:
            event = generate_normal_event(base_time, session_id, i)
        
        events.append(event)
        
        # Progress indicator
        if (i + 1) % 1_000_000 == 0:
            print(f"  Generated {i + 1:,} events...")
    
    return events


def run_stress_test(events: list, results_file: str = "results/stress_test_results.json"):
    """Run the stress test through the SCAPE engine.
    
    Args:
        events: List of CloudTrail events.
        results_file: Path to save results JSON.
    
    Returns:
        Dict with throughput, memory, and latency metrics.
    """
    print(f"\n[STRESS TEST] Training engine on first 100k events...")
    engine = SCAPEEngine()
    engine.train_from_logs(events[:100_000])
    print("  Training complete.")
    
    # Get baseline memory
    process = psutil.Process()
    mem_baseline = process.memory_info().rss / (1024 ** 2)  # MB
    print(f"  Baseline memory: {mem_baseline:.1f} MB")
    
    print(f"\n[STRESS TEST] Evaluating {len(events):,} events...")
    start_time = time.time()
    latencies = []
    decisions = {"BLOCK": 0, "ALLOW": 0}
    
    prev_action = None
    prev_ts = None
    
    for idx, event in enumerate(events):
        event_start = time.time()
        result = engine.evaluate_event(prev_action, event, prev_timestamp=prev_ts)
        event_latency = (time.time() - event_start) * 1000  # milliseconds
        
        latencies.append(event_latency)
        decisions[result["decision"]] += 1
        
        prev_action = event.get("eventName")
        prev_ts = engine._parse_time(event.get("eventTime", ""))
        
        # Progress and periodic memory check
        if (idx + 1) % 1_000_000 == 0:
            elapsed = time.time() - start_time
            throughput = (idx + 1) / elapsed
            mem_current = process.memory_info().rss / (1024 ** 2)
            print(f"  {idx + 1:,} events | {throughput:,.0f} ev/s | "
                  f"Memory: {mem_current:.1f} MB | "
                  f"Blocks: {decisions['BLOCK']}, Allows: {decisions['ALLOW']}")
    
    elapsed_total = time.time() - start_time
    throughput = len(events) / elapsed_total
    mem_final = process.memory_info().rss / (1024 ** 2)
    mem_peak = max(mem_baseline, mem_final)
    
    # Calculate percentiles
    sorted_latencies = sorted(latencies)
    p50_latency = sorted_latencies[len(sorted_latencies) // 2]
    p99_latency = sorted_latencies[int(len(sorted_latencies) * 0.99)]
    p999_latency = sorted_latencies[int(len(sorted_latencies) * 0.999)]
    
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "throughput_events_per_second": throughput,
        "elapsed_seconds": elapsed_total,
        "memory_baseline_mb": mem_baseline,
        "memory_final_mb": mem_final,
        "memory_peak_mb": mem_peak,
        "decisions": decisions,
        "latency_p50_ms": p50_latency,
        "latency_p99_ms": p99_latency,
        "latency_p999_ms": p999_latency,
        "meets_production_target": throughput >= 50_000,
    }
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"STRESS TEST RESULTS")
    print(f"{'='*70}")
    print(f"Total events processed: {len(events):,}")
    print(f"Throughput:             {throughput:,.0f} events/second")
    print(f"Elapsed time:           {elapsed_total:.1f} seconds")
    print(f"Memory (baseline):      {mem_baseline:.1f} MB")
    print(f"Memory (final):         {mem_final:.1f} MB")
    print(f"Memory (peak):          {mem_peak:.1f} MB")
    print(f"Decisions: BLOCK={decisions['BLOCK']:,}, ALLOW={decisions['ALLOW']:,}")
    print(f"Latency (P50):          {p50_latency:.4f} ms")
    print(f"Latency (P99):          {p99_latency:.4f} ms")
    print(f"Latency (P99.9):        {p999_latency:.4f} ms")
    print(f"Production target (≥50k ev/s): {'PASS' if results['meets_production_target'] else 'FAIL'}")
    print(f"{'='*70}\n")
    
    # Save results
    os.makedirs(os.path.dirname(results_file) or ".", exist_ok=True)
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {results_file}")
    
    return results


if __name__ == "__main__":
    print("SCAPE Stress / Scalability Test")
    print("=" * 70)
    
    # Check for command-line arguments
    num_events = 10_000_000
    if len(sys.argv) > 1:
        try:
            num_events = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [num_events]")
            sys.exit(1)
    
    print(f"\nGenerating {num_events:,} synthetic events (99.9% normal, 0.1% attack)...")
    events = generate_synthetic_dataset(num_events, attack_ratio=0.001)
    
    results = run_stress_test(events)
    
    # Exit with error if production target not met
    if not results["meets_production_target"]:
        print(f"\nWARNING: Throughput {results['throughput_events_per_second']:.0f} ev/s "
              f"is below the production target of 50,000 ev/s")
        sys.exit(1)
