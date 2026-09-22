"""Phase 1: Proper Evaluation Methodology.

1.3: Injects attack logs into normal traffic at configurable ratios
1.4: Computes FPR on clean logs
1.5: Comparison table (SCAPE vs Static Baseline vs GuardDuty placeholder)

Usage:
  python evaluation/full_evaluation.py
  python evaluation/full_evaluation.py --attack-ratio 0.001 --clean-fpr
"""

import json
import os
import sys
import random
from collections import defaultdict
from copy import deepcopy

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine


def load_records(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("Records", [])
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported format")


# ======================================================================
# Phase 1.3: Inject attacks into normal traffic
# ======================================================================
def inject_attacks(normal: list, attacks: list, ratio: float = 0.001) -> tuple:
    """Merge attack events into normal traffic at the given ratio.

    Returns (mixed_events, labels) where label=True means attack.
    """
    n_attacks = max(1, int(len(normal) * ratio))
    if n_attacks > len(attacks):
        # replicate attacks if not enough
        attacks_sampled = attacks * (n_attacks // len(attacks) + 1)
        attacks_sampled = attacks_sampled[:n_attacks]
    else:
        attacks_sampled = random.sample(attacks, n_attacks)

    mixed = list(normal)
    labels = [False] * len(normal)

    # Insert attacks at random positions
    for atk in attacks_sampled:
        pos = random.randint(0, len(mixed))
        mixed.insert(pos, atk)
        labels.insert(pos, True)

    return mixed, labels


# ======================================================================
# Evaluators
# ======================================================================
def evaluate_scape(engine: SCAPEEngine, events: list, labels: list) -> dict:
    tp = fp = tn = fn = 0
    prev_action = None
    prev_ts = None
    decisions = defaultdict(int)

    for ev, is_attack in zip(events, labels):
        result = engine.evaluate_event(prev_action, ev, prev_timestamp=prev_ts)
        pred_anomaly = result["decision"] != "ALLOW"
        decisions[result["decision"]] += 1

        if pred_anomaly and is_attack: tp += 1
        elif pred_anomaly and not is_attack: fp += 1
        elif not pred_anomaly and not is_attack: tn += 1
        elif not pred_anomaly and is_attack: fn += 1

        prev_action = ev.get("eventName")
        prev_ts = engine._parse_time(ev.get("eventTime", ""))

    return _compute_metrics(tp, fp, tn, fn, decisions)


def evaluate_static_baseline(allowed_actions: set, events: list, labels: list) -> dict:
    """Static IAM baseline: block anything not in the allowed set."""
    tp = fp = tn = fn = 0
    decisions = defaultdict(int)

    for ev, is_attack in zip(events, labels):
        action = ev.get("eventName", "Unknown")
        pred_anomaly = action not in allowed_actions
        decision = "BLOCK" if pred_anomaly else "ALLOW"
        decisions[decision] += 1

        if pred_anomaly and is_attack: tp += 1
        elif pred_anomaly and not is_attack: fp += 1
        elif not pred_anomaly and not is_attack: tn += 1
        elif not pred_anomaly and is_attack: fn += 1

    return _compute_metrics(tp, fp, tn, fn, decisions)


def _compute_metrics(tp, fp, tn, fn, decisions):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": fpr, "accuracy": accuracy,
        "decisions": dict(decisions),
    }


# ======================================================================
# Phase 1.4: Clean FPR computation
# ======================================================================
def compute_clean_fpr(engine: SCAPEEngine, clean_events: list) -> dict:
    """Run SCAPE on guaranteed-clean events and compute FPR."""
    labels = [False] * len(clean_events)
    return evaluate_scape(engine, clean_events, labels)


# ======================================================================
# Main
# ======================================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Full SCAPE evaluation (Phase 1).")
    parser.add_argument("--attack-ratio", type=float, default=0.001,
                        help="Ratio of attack events to inject (default: 1 per 1000).")
    parser.add_argument("--clean-fpr", action="store_true",
                        help="Also compute FPR on a separate clean log set.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    args = parser.parse_args()

    random.seed(args.seed)

    # Load model
    model_path = os.path.join(PROJECT_ROOT, "models", "my_engine.json")
    engine = SCAPEEngine.load(model_path)
    print(f"Loaded model from {model_path}")

    # Load data
    normal_path = os.path.join(PROJECT_ROOT, "data", "logs", "my_cloudtrail_scape.json")
    attack_path = os.path.join(PROJECT_ROOT, "data", "test_anomalous.json")

    if not os.path.exists(normal_path):
        normal_path = os.path.join(PROJECT_ROOT, "data", "normal_traffic.json")

    normal_logs = load_records(normal_path)
    attack_logs = load_records(attack_path)

    print(f"Normal events: {len(normal_logs)}")
    print(f"Attack events: {len(attack_logs)}")
    print(f"Attack ratio:  {args.attack_ratio}")

    # Create mixed test set (Phase 1.3)
    mixed, labels = inject_attacks(normal_logs, attack_logs, ratio=args.attack_ratio)
    n_attacks = sum(labels)
    n_normal = len(labels) - n_attacks
    print(f"\nMixed test set: {len(mixed)} events ({n_attacks} attacks, {n_normal} normal)")

    # Build static baseline allowed set from training data
    allowed_actions = set(engine.global_action_counts.keys())

    # Evaluate SCAPE
    print("\n--- Evaluating SCAPE ---")
    scape_results = evaluate_scape(engine, mixed, labels)

    # Evaluate Static Baseline
    print("--- Evaluating Static IAM Baseline ---")
    baseline_results = evaluate_static_baseline(allowed_actions, mixed, labels)

    # Placeholder for GuardDuty (Phase 1.5)
    # In production: query GuardDuty findings for the same time period
    guardduty_results = {
        "precision": "N/A", "recall": "N/A", "f1": "N/A",
        "fpr": "N/A", "accuracy": "N/A",
        "note": "Enable GuardDuty and collect findings for the same period",
    }

    # Print comparison table
    print("\n" + "=" * 75)
    print("EVALUATION RESULTS: SCAPE vs Static Baseline vs GuardDuty")
    print("=" * 75)
    print(f"Test set: {len(mixed)} events ({n_attacks} attacks injected at {args.attack_ratio} ratio)")
    print()

    header = f"{'Metric':<20} {'SCAPE':>12} {'Static IAM':>12} {'GuardDuty':>12}"
    print(header)
    print("-" * 60)
    for metric in ["precision", "recall", "f1", "fpr", "accuracy"]:
        s_val = scape_results[metric]
        b_val = baseline_results[metric]
        g_val = guardduty_results.get(metric, "N/A")

        s_str = f"{s_val:.4f}" if isinstance(s_val, float) else str(s_val)
        b_str = f"{b_val:.4f}" if isinstance(b_val, float) else str(b_val)
        g_str = f"{g_val:.4f}" if isinstance(g_val, float) else str(g_val)

        print(f"{metric:<20} {s_str:>12} {b_str:>12} {g_str:>12}")

    print("-" * 60)
    print(f"{'TP':<20} {scape_results['tp']:>12} {baseline_results['tp']:>12}")
    print(f"{'FP':<20} {scape_results['fp']:>12} {baseline_results['fp']:>12}")
    print(f"{'TN':<20} {scape_results['tn']:>12} {baseline_results['tn']:>12}")
    print(f"{'FN':<20} {scape_results['fn']:>12} {baseline_results['fn']:>12}")

    # Phase 1.4: Clean FPR
    if args.clean_fpr:
        print("\n--- Phase 1.4: Clean FPR Analysis ---")
        # Use test_normal.json or a separate split
        clean_path = os.path.join(PROJECT_ROOT, "data", "test_normal.json")
        if os.path.exists(clean_path):
            clean_logs = load_records(clean_path)
            fpr_results = compute_clean_fpr(engine, clean_logs)
            print(f"Clean events:    {len(clean_logs)}")
            print(f"False positives: {fpr_results['fp']}")
            print(f"Clean FPR:       {fpr_results['fpr']:.4f} ({fpr_results['fpr']*100:.2f}%)")
            for dec, cnt in fpr_results["decisions"].items():
                print(f"  {dec}: {cnt}")
        else:
            print("No clean test set found at data/test_normal.json")

    print("\n" + "=" * 75)


if __name__ == "__main__":
    main()
