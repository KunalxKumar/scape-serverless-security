"""Step 3: Test SCAPE model against the flAWS CloudTrail dataset.

Runs the trained model on every event, computes per-event phi scores,
applies the anomaly threshold tau, and generates detection statistics.

Usage:
    python pipeline/test.py [--model models/flaws_engine.json]
    python pipeline/test.py --model models/my_engine.json --max-rows 500000
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.utils import (
    load_flaws_csv, group_by_session, print_header, print_table, DATASET_PATH,
)
from src.scape_engine import SCAPEEngine


def main():
    parser = argparse.ArgumentParser(description="Test SCAPE on flAWS data")
    parser.add_argument("--model", default="models/flaws_engine.json",
                        help="Trained model path")
    parser.add_argument("--input", default=DATASET_PATH, help="Raw CSV path")
    parser.add_argument("--preprocessed", default="data/flaws_preprocessed.json",
                        help="Preprocessed JSON path")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max events to test (None = all)")
    parser.add_argument("--output-json", default="results/flaws_results.json",
                        help="JSON results output")
    parser.add_argument("--output-txt", default="results/flaws_results.txt",
                        help="Text results output")
    parser.add_argument("--batch-size", type=int, default=50000,
                        help="Progress report every N events")
    args = parser.parse_args()

    print_header("SCAPE Pipeline: Step 3 - Testing")

    # Load model
    if not os.path.exists(args.model):
        # Fallback to existing model
        alt = "models/my_engine.json"
        if os.path.exists(alt):
            print(f"  Model {args.model} not found, using {alt}")
            args.model = alt
        else:
            print(f"ERROR: No model found. Run pipeline/train.py first.")
            sys.exit(1)

    print(f"  Model: {args.model}")
    engine = SCAPEEngine.load(args.model)
    print(f"  tau = {engine.tau:.4f}")
    print(f"  Vocabulary: {len(engine.action_vocabulary)} actions")

    # Load test data
    if args.preprocessed and os.path.exists(args.preprocessed):
        print(f"  Loading preprocessed: {args.preprocessed}")
        with open(args.preprocessed, "r", encoding="utf-8") as f:
            data = json.load(f)
        events = data["events"]
        if args.max_rows:
            events = events[:args.max_rows]
    else:
        print(f"  Loading CSV: {args.input}")
        events = load_flaws_csv(args.input, max_rows=args.max_rows)

    print(f"  Test events: {len(events):,}")

    # Group by session for sequential scoring
    sessions = group_by_session(events)
    print(f"  Sessions: {len(sessions)}")

    # Score all events
    print_header("Scoring Events")
    t0 = time.time()

    all_results = []
    phis = []
    decisions = Counter()
    anomalous_actions = Counter()
    violation_counts = Counter()
    anomalous_sequences = []
    events_processed = 0

    for sid, session_events in sessions.items():
        prev_action = None
        prev_ts = None
        session_anomalies = []

        for ev in session_events:
            result = engine.evaluate_event(
                prev_action=prev_action,
                curr_event=ev,
                prev_timestamp=prev_ts,
            )
            phi = result["phi"]
            decision = result["decision"]

            phis.append(phi)
            decisions[decision] += 1

            if decision == "BLOCK":
                action = ev.get("eventName", "Unknown")
                anomalous_actions[action] += 1
                for v in result.get("violations", []):
                    violation_counts[v] += 1
                session_anomalies.append({
                    "action": action,
                    "phi": round(phi, 6),
                    "violations": result.get("violations", []),
                    "time": ev.get("eventTime", ""),
                    "source": ev.get("eventSource", ""),
                })

            prev_action = ev.get("eventName")
            if ev.get("eventTime"):
                try:
                    prev_ts = engine._parse_time(ev["eventTime"])
                except Exception:
                    prev_ts = None

            events_processed += 1
            if events_processed % args.batch_size == 0:
                elapsed = time.time() - t0
                rate = events_processed / elapsed
                pct_block = 100 * decisions["BLOCK"] / events_processed
                print(f"  [{events_processed:>10,} / {len(events):,}] "
                      f"{rate:,.0f} ev/s | "
                      f"BLOCK: {decisions['BLOCK']:,} ({pct_block:.1f}%)")

        # Save first 50 anomalous sequences for the report
        if session_anomalies and len(anomalous_sequences) < 50:
            anomalous_sequences.append({
                "session_id": sid[:80],
                "total_events": len(session_events),
                "anomalies": len(session_anomalies),
                "sequence": session_anomalies[:10],
            })

    elapsed = time.time() - t0

    # Compute phi distribution
    import math
    phi_buckets = Counter()
    for p in phis:
        bucket = f"{min(int(p * 10), 9) / 10:.1f}-{min(int(p * 10) + 1, 10) / 10:.1f}"
        phi_buckets[bucket] += 1

    # Results
    total = len(phis)
    n_block = decisions["BLOCK"]
    n_allow = decisions["ALLOW"]
    pct_anomaly = 100 * n_block / max(1, total)
    avg_phi = sum(phis) / max(1, total)
    min_phi = min(phis) if phis else 0
    max_phi = max(phis) if phis else 0

    print_header("Results Summary")
    print(f"  Total events scored: {total:,}")
    print(f"  BLOCK (anomaly):     {n_block:,} ({pct_anomaly:.2f}%)")
    print(f"  ALLOW (normal):      {n_allow:,} ({100 - pct_anomaly:.2f}%)")
    print(f"  Elapsed:             {elapsed:.1f}s ({total/elapsed:,.0f} events/sec)")
    print(f"  tau:                 {engine.tau:.4f}")
    print(f"  Phi: min={min_phi:.4f}, avg={avg_phi:.4f}, max={max_phi:.4f}")

    print("\n  Phi Score Distribution:")
    for bucket in sorted(phi_buckets.keys()):
        count = phi_buckets[bucket]
        bar = "#" * min(50, int(50 * count / max(phi_buckets.values())))
        print(f"    {bucket}: {count:>10,}  {bar}")

    print("\n  Top 20 Anomalous Actions:")
    print_table(
        ["Action", "Count", "Pct of Anomalies"],
        [[a, f"{c:,}", f"{100*c/max(1,n_block):.1f}%"]
         for a, c in anomalous_actions.most_common(20)],
        [40, 12, 18],
    )

    print("\n  Violation Dimension Breakdown:")
    print_table(
        ["Dimension", "Count", "Pct"],
        [[d, f"{c:,}", f"{100*c/max(1,sum(violation_counts.values())):.1f}%"]
         for d, c in violation_counts.most_common()],
        [12, 12, 8],
    )

    if anomalous_sequences:
        print("\n  Sample Anomalous Sequences (first 3):")
        for seq in anomalous_sequences[:3]:
            print(f"\n    Session: {seq['session_id']}")
            print(f"    Events: {seq['total_events']}, Anomalies: {seq['anomalies']}")
            for ev in seq["sequence"][:5]:
                print(f"      [{ev['time']}] {ev['action']} "
                      f"-> phi={ev['phi']:.4f} violations={ev['violations']}")

    # Save results
    results = {
        "metadata": {
            "model": args.model,
            "tau": engine.tau,
            "dataset": "flAWS CloudTrail (Kaggle)",
            "total_events": total,
            "elapsed_seconds": round(elapsed, 2),
        },
        "summary": {
            "total_events": total,
            "anomalies_detected": n_block,
            "anomaly_percentage": round(pct_anomaly, 4),
            "normal_events": n_allow,
            "phi_mean": round(avg_phi, 6),
            "phi_min": round(min_phi, 6),
            "phi_max": round(max_phi, 6),
        },
        "phi_distribution": dict(sorted(phi_buckets.items())),
        "top_anomalous_actions": [
            {"action": a, "count": c}
            for a, c in anomalous_actions.most_common(50)
        ],
        "violation_breakdown": dict(violation_counts.most_common()),
        "sample_anomalous_sequences": anomalous_sequences[:20],
    }

    os.makedirs(os.path.dirname(args.output_json), exist_ok=True)

    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  JSON results saved to {args.output_json}")

    # Text report
    lines = []
    lines.append("=" * 60)
    lines.append("SCAPE Anomaly Detection Results - flAWS Dataset")
    lines.append("=" * 60)
    lines.append(f"Model:              {args.model}")
    lines.append(f"Threshold (tau):    {engine.tau:.4f}")
    lines.append(f"Total Events:       {total:,}")
    lines.append(f"Anomalies (BLOCK):  {n_block:,} ({pct_anomaly:.2f}%)")
    lines.append(f"Normal (ALLOW):     {n_allow:,} ({100-pct_anomaly:.2f}%)")
    lines.append(f"")
    lines.append(f"Phi Statistics:")
    lines.append(f"  Mean: {avg_phi:.6f}")
    lines.append(f"  Min:  {min_phi:.6f}")
    lines.append(f"  Max:  {max_phi:.6f}")
    lines.append(f"")
    lines.append("Phi Distribution:")
    for bucket in sorted(phi_buckets.keys()):
        count = phi_buckets[bucket]
        lines.append(f"  {bucket}: {count:>10,}")
    lines.append("")
    lines.append("Top Anomalous Actions:")
    for a, c in anomalous_actions.most_common(30):
        lines.append(f"  {a:<40} {c:>8,}")
    lines.append("")
    lines.append("Violation Dimensions:")
    for d, c in violation_counts.most_common():
        lines.append(f"  {d}: {c:,}")

    with open(args.output_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  Text results saved to {args.output_txt}")

    print_header("Testing Complete")


if __name__ == "__main__":
    main()
