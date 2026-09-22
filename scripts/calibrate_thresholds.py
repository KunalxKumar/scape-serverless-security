#!/usr/bin/env python3
"""Threshold Calibration Script for SCAPEEngine.

Takes a held-out set of benign logs (not used for training) and finds the
optimal anomaly score threshold (τ) that yields a target False Positive Rate.

Uses F2-score to prefer recall over precision, ensuring we catch attacks while
keeping FPR under control.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scape_engine import SCAPEEngine


def _make_event(action, bucket=None, table=None, session="s-0",
                time_str="2026-04-12T12:00:00Z", volume=None):
    """Helper to build a CloudTrail-like event dict."""
    ev = {
        "eventName": action,
        "requestParameters": {},
        "eventTime": time_str,
        "sessionId": session,
    }
    if bucket:
        ev["requestParameters"]["bucketName"] = bucket
    if table:
        ev["requestParameters"]["tableName"] = table
    if volume is not None:
        ev["additionalEventData"] = {"bytesTransferredOut": volume}
    return ev


def generate_training_logs(num_sessions: int = 100) -> List[dict]:
    """Generate representative normal training logs."""
    logs = []
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    idx = 0
    
    for session in range(num_sessions):
        # Each session: normal s3 workflow
        for i in range(5):
            for action in ["s3:GetObject", "s3:PutObject", "logs:PutLogEvents"]:
                logs.append(_make_event(
                    action,
                    bucket="prod-bucket" if action == "s3:GetObject" else "log-bucket",
                    table=None,
                    session=f"s-train-{session}",
                    time_str=(base + timedelta(seconds=idx)).isoformat() + "Z",
                    volume=2000 if action in ["s3:GetObject", "s3:PutObject"] else None
                ))
                idx += 1
    
    return logs


def generate_validation_logs(num_events: int = 10_000,
                            attack_ratio: float = 0.01) -> Tuple[List[dict], List[bool]]:
    """Generate validation logs with known benign/attack labels.
    
    Args:
        num_events: Total number of validation events.
        attack_ratio: Fraction of events that are attacks.
    
    Returns:
        Tuple of (events, labels) where labels[i] = True if events[i] is an attack.
    """
    events = []
    labels = []
    base = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
    idx = 0
    
    num_attacks = int(num_events * attack_ratio)
    
    # Generate normal events
    for i in range(num_events - num_attacks):
        event = _make_event(
            "s3:GetObject",
            bucket="prod-bucket",
            session=f"s-valid-{i // 100}",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z",
            volume=2000
        )
        events.append(event)
        labels.append(False)
        idx += 1
    
    # Generate attack events
    import random
    for i in range(num_attacks):
        attack_type = random.choice(["unseen_action", "unseen_resource", "burst"])
        
        if attack_type == "unseen_action":
            event = _make_event(
                "iam:CreateAccessKey",
                session=f"s-atk-{i}",
                time_str=(base + timedelta(seconds=idx)).isoformat() + "Z"
            )
        elif attack_type == "unseen_resource":
            event = _make_event(
                "s3:PutObject",
                bucket=f"evil-bucket-{i}",
                session=f"s-valid-{i}",
                time_str=(base + timedelta(seconds=idx)).isoformat() + "Z",
                volume=1_000_000
            )
        else:  # burst
            event = _make_event(
                "s3:PutObject",
                bucket="prod-bucket",
                session=f"s-burst-{i}",
                time_str=(base + timedelta(microseconds=idx * 100)).isoformat() + "Z",
                volume=random.randint(100, 10000)
            )
        
        events.append(event)
        labels.append(True)
        idx += 1
    
    return events, labels


def calibrate_engine(training_logs: List[dict],
                     validation_events: List[dict],
                     validation_labels: List[bool],
                     target_fpr: float = 0.01) -> dict:
    """Calibrate the SCAPE engine to a target FPR using F2 optimization.
    
    Args:
        training_logs: Logs to train the engine on.
        validation_events: Held-out validation events.
        validation_labels: Ground-truth labels (True = attack, False = benign).
        target_fpr: Target False Positive Rate (default 1%).
    
    Returns:
        Dict with calibration results.
    """
    print(f"\n[CALIBRATION] Training engine on {len(training_logs):,} logs...")
    engine = SCAPEEngine()
    engine.train_from_logs(training_logs)
    print(f"  Training complete.")
    
    # Use calibrate() to find optimal tau
    print(f"\n[CALIBRATION] Running F2-based optimization on {len(validation_events):,} events...")
    optimal_tau = engine.calibrate(validation_events, validation_labels)
    print(f"  Optimal τ found: {optimal_tau:.4f}")
    
    # Evaluate at the optimal tau
    print(f"\n[CALIBRATION] Evaluating at optimal τ = {optimal_tau:.4f}...")
    tp = fp = tn = fn = 0
    
    prev_action = None
    prev_ts = None
    
    for event, is_attack in zip(validation_events, validation_labels):
        result = engine.evaluate_event(prev_action, event, prev_timestamp=prev_ts)
        is_blocked = result["decision"] == "BLOCK"
        
        if is_attack:
            if is_blocked:
                tp += 1
            else:
                fn += 1
        else:
            if is_blocked:
                fp += 1
            else:
                tn += 1
        
        prev_action = event.get("eventName")
        prev_ts = engine._parse_time(event.get("eventTime", ""))
    
    # Calculate metrics
    total_benign = fp + tn
    fpr = fp / total_benign if total_benign > 0 else 0.0
    
    total_attacks = tp + fn
    recall = tp / total_attacks if total_attacks > 0 else 0.0
    
    total_positives = tp + fp
    precision = tp / total_positives if total_positives > 0 else 0.0
    
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_fpr": target_fpr,
        "optimal_tau": optimal_tau,
        "metrics": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "fpr": fpr,
            "recall": recall,
            "precision": precision,
        },
        "total_validation_events": len(validation_events),
        "total_attacks": total_attacks,
        "total_benign": total_benign,
    }
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"CALIBRATION RESULTS")
    print(f"{'='*70}")
    print(f"Optimal threshold (τ): {optimal_tau:.4f}")
    print(f"False Positive Rate:   {fpr:.2%} (target: {target_fpr:.2%})")
    print(f"Recall (TP Rate):      {recall:.2%}")
    print(f"Precision:             {precision:.2%}")
    print(f"Confusion matrix:")
    print(f"  TP={tp:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TN={tn:,}")
    print(f"{'='*70}\n")
    
    return results


def main():
    """Main entry point."""
    print("SCAPE Threshold Calibration")
    print("=" * 70)
    
    # Generate datasets
    print("\n[SETUP] Generating training and validation datasets...")
    training_logs = generate_training_logs(num_sessions=100)
    validation_events, validation_labels = generate_validation_logs(
        num_events=10_000,
        attack_ratio=0.01  # 1% attacks
    )
    
    # Calibrate
    results = calibrate_engine(
        training_logs,
        validation_events,
        validation_labels,
        target_fpr=0.01
    )
    
    # Save results
    os.makedirs("results", exist_ok=True)
    results_file = "results/calibration_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {results_file}")
    
    return results


if __name__ == "__main__":
    import random
    main()
