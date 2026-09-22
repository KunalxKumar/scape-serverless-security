"""Step 2: Train SCAPE model on the flAWS CloudTrail dataset.

Trains the C0-C5 anomaly detection model using the preprocessed
CloudTrail events. For the flAWS dataset (which is entirely
adversarial reconnaissance), we train on a baseline of the MOST
frequent actions to establish what "normal-ish" looks like, then
detect deviations.

Strategy:
  - Use the top-N most frequent actions (representing routine
    service behavior) as the "normal" training set.
  - Or use a separate normal traffic file if available.
  - Calibrate tau on a validation split.

Usage:
    python pipeline/train.py [--preprocessed data/flaws_preprocessed.json]
    python pipeline/train.py --normal-traffic data/normal_traffic.json
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.utils import (
    load_flaws_csv, group_by_session, compute_stats,
    print_header, DATASET_PATH,
)
from src.scape_engine import SCAPEEngine


def load_events(args) -> list:
    """Load events from preprocessed JSON or raw CSV."""
    if args.preprocessed and os.path.exists(args.preprocessed):
        print(f"Loading preprocessed data from {args.preprocessed}...")
        with open(args.preprocessed, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["events"]
    else:
        print(f"Loading raw CSV from {args.input}...")
        return load_flaws_csv(args.input, max_rows=args.max_rows)


def main():
    parser = argparse.ArgumentParser(description="Train SCAPE on flAWS data")
    parser.add_argument("--input", default=DATASET_PATH, help="Raw CSV path")
    parser.add_argument("--preprocessed", default="data/flaws_preprocessed.json",
                        help="Preprocessed JSON path")
    parser.add_argument("--normal-traffic", default="data/normal_traffic.json",
                        help="Existing normal traffic JSON (preferred)")
    parser.add_argument("--output", default="models/flaws_engine.json",
                        help="Output model path")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max CSV rows to load")
    parser.add_argument("--train-fraction", type=float, default=0.7,
                        help="Fraction of events for training (rest for calibration)")
    args = parser.parse_args()

    print_header("SCAPE Pipeline: Step 2 - Training")

    # Strategy 1: Use existing normal traffic if available
    if os.path.exists(args.normal_traffic):
        print(f"[STRATEGY] Using existing normal traffic: {args.normal_traffic}")
        with open(args.normal_traffic, "r", encoding="utf-8") as f:
            normal_data = json.load(f)
        if isinstance(normal_data, dict):
            train_events = normal_data.get("Records", normal_data.get("records", [normal_data]))
        else:
            train_events = normal_data
        print(f"  Normal events loaded: {len(train_events):,}")
    else:
        # Strategy 2: Extract "normal-looking" events from flAWS
        print("[STRATEGY] No normal traffic file found.")
        print("  Extracting baseline from most-frequent actions in flAWS data.")

        all_events = load_events(args)
        print(f"  Total events: {len(all_events):,}")

        # Find the top routine actions (console/service noise)
        from collections import Counter
        action_counts = Counter(ev["eventName"] for ev in all_events)
        # Top 10 most frequent are likely service/console noise
        top_actions = {a for a, _ in action_counts.most_common(10)}
        print(f"  Top-10 routine actions: {top_actions}")

        # Use events from the top actions as "normal" baseline
        train_events = [ev for ev in all_events if ev["eventName"] in top_actions]
        print(f"  Baseline events (top-10 actions): {len(train_events):,}")

    # Split into train/calibration
    split_idx = int(len(train_events) * args.train_fraction)
    train_set = train_events[:split_idx]
    cal_set = train_events[split_idx:]
    print(f"  Training set:    {len(train_set):,}")
    print(f"  Calibration set: {len(cal_set):,}")

    # Train
    print_header("Training SCAPE Engine")
    engine = SCAPEEngine()
    t0 = time.time()
    engine.train_from_logs(train_set)
    t_train = time.time() - t0
    print(f"  Training completed in {t_train:.1f}s")
    print(f"  Vocabulary size:     {len(engine.action_vocabulary)}")
    print(f"  Total events seen:   {engine.total_events:,}")
    print(f"  Unique sessions:     {len(engine.seen_sessions)}")
    print(f"  Transition pairs:    {len(engine.transition_counts)}")
    print(f"  Resource bindings:   {sum(len(v) for v in engine.resource_sets.values())}")
    print(f"  Timing stats for:    {len(engine.timing_stats)} actions")

    # Calibrate tau
    if cal_set:
        print_header("Calibrating Threshold (tau)")
        # For flAWS data: everything is technically anomalous,
        # so we calibrate to produce BLOCK for rare actions
        # and ALLOW for the baseline routine actions.
        #
        # We label the calibration set as "normal" (False)
        # and inject synthetic attacks as "attack" (True).
        synthetic_attacks = []
        for i in range(20):
            synthetic_attacks.append({
                "eventName": f"SyntheticAttack{i}",
                "eventSource": "attack.amazonaws.com",
                "eventTime": "2026-01-01T00:00:00Z",
                "sessionId": f"attacker-{i}",
                "userIdentity": {"type": "Root", "principalId": "999",
                                 "arn": f"arn:aws:iam::999:root", "accountId": "999",
                                 "accessKeyId": "", "userName": ""},
                "requestParameters": {},
            })

        cal_events = cal_set + synthetic_attacks
        cal_labels = [False] * len(cal_set) + [True] * len(synthetic_attacks)
        tau = engine.calibrate(cal_events, cal_labels)
        print(f"  Calibrated tau = {tau:.4f}")
    else:
        print("  [SKIP] No calibration set available")

    # Save model
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    engine.save(args.output)
    size_kb = os.path.getsize(args.output) / 1024
    print(f"\n  Model saved to {args.output} ({size_kb:.1f} KB)")

    print_header("Training Complete")
    print(f"  Model: {args.output}")
    print(f"  tau:   {engine.tau:.4f}")
    print(f"  Next:  python pipeline/test.py --model {args.output}")


if __name__ == "__main__":
    main()
