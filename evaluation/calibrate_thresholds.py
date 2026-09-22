"""Phase 2.1: Threshold (τ) calibration for the formal SCAPE engine.

Loads a trained model and a clean log file, scores every event to obtain
Φ values, computes percentile-based thresholds, and optionally uses the
engine's built-in F2-score calibration.

Usage:
  python evaluation/calibrate_thresholds.py --save
  python evaluation/calibrate_thresholds.py --fpr-ceiling 0.005 --save
"""

import json
import math
import os
import sys
from collections import defaultdict

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


def percentile(sorted_vals, p):
    """Return the value at the p-th percentile (0-100)."""
    if not sorted_vals:
        return 0.0
    idx = int(len(sorted_vals) * p / 100.0)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


def score_events(engine, events):
    """Score all events and return list of Φ values."""
    phis = []
    prev_action = None
    prev_ts = None
    for ev in events:
        action = ev.get("eventName", "Unknown")
        ts_str = ev.get("eventTime", "")
        timestamp = engine._parse_time(ts_str) if ts_str else None

        result = engine.evaluate_event(prev_action, ev, prev_timestamp=prev_ts)
        phis.append(result["phi"])
        prev_action = action
        prev_ts = timestamp
    return phis


def evaluate_at_threshold(normal_phis, attack_phis, tau):
    """Evaluate BLOCK-if-phi<tau at a given tau."""
    fp = sum(1 for p in normal_phis if p < tau)
    tn = len(normal_phis) - fp
    tp = sum(1 for p in attack_phis if p < tau)
    fn = len(attack_phis) - tp
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0
    return {"tau": tau, "fpr": fpr, "tpr": tpr, "precision": prec, "recall": tpr, "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Calibrate SCAPE τ threshold.")
    parser.add_argument("--model", default=os.path.join(PROJECT_ROOT, "models", "my_engine.json"))
    parser.add_argument("--normal-logs", help="Path to clean normal log file.")
    parser.add_argument("--attack-logs", help="Path to attack log file (optional).")
    parser.add_argument("--save", action="store_true", help="Write calibrated τ back to model.")
    parser.add_argument("--fpr-ceiling", type=float, default=0.01, help="Max FPR for threshold selection.")
    args = parser.parse_args()

    # Load model
    engine = SCAPEEngine.load(args.model)
    print(f"Loaded model from {args.model}")

    # Find normal logs
    normal_path = args.normal_logs
    if not normal_path:
        candidates = [
            os.path.join(PROJECT_ROOT, "data", "logs", "my_cloudtrail_scape.json"),
            os.path.join(PROJECT_ROOT, "data", "normal_traffic.json"),
            os.path.join(PROJECT_ROOT, "data", "test_normal.json"),
        ]
        for c in candidates:
            if os.path.exists(c):
                normal_path = c
                break
    if not normal_path or not os.path.exists(normal_path):
        print("ERROR: No normal log file found. Use --normal-logs.")
        return

    normal_logs = load_records(normal_path)
    print(f"Normal events: {len(normal_logs)} from {os.path.basename(normal_path)}")

    # Score
    print("Scoring normal events...")
    normal_phis = score_events(engine, normal_logs)
    normal_sorted = sorted(normal_phis)

    # Percentiles (Φ is in [0,1], lower = more anomalous)
    pcts = [0, 1, 5, 10, 25, 50, 75, 90, 95, 99]
    print(f"\n=== Normal Phi Percentiles ===")
    print(f"  {'Percentile':>12} {'Phi':>10}")
    print("  " + "-" * 25)
    for p in pcts:
        val = percentile(normal_sorted, p)
        print(f"  {p:>11}% {val:>10.6f}")

    # Attack evaluation if available
    attack_path = args.attack_logs
    if not attack_path:
        attack_path = os.path.join(PROJECT_ROOT, "data", "test_anomalous.json")

    if os.path.exists(attack_path):
        attack_logs = load_records(attack_path)
        print(f"\nAttack events: {len(attack_logs)} from {os.path.basename(attack_path)}")
        attack_phis = score_events(engine, attack_logs)
        attack_sorted = sorted(attack_phis)

        print(f"\n=== Attack Phi Percentiles ===")
        for p in [0, 25, 50, 75, 90, 100]:
            val = percentile(attack_sorted, p)
            print(f"  P{p:<6} {val:>10.6f}")

        # Use engine's built-in F2 calibration
        print("\n=== F2-Score Calibration ===")
        # Build combined set with labels
        combined_events = normal_logs + attack_logs
        combined_labels = [False] * len(normal_logs) + [True] * len(attack_logs)
        best_tau = engine.calibrate(combined_events, combined_labels)
        print(f"  Optimal tau (F2-maximising): {best_tau:.4f}")

        # Sweep for comparison
        sweep_vals = sorted(set([best_tau] +
                                [i / 100.0 for i in range(0, 101, 5)]))
        print(f"\n{'tau':>10} {'FPR':>8} {'TPR':>8} {'Prec':>8} {'F1':>8}")
        print("-" * 48)
        for tau in sweep_vals:
            r = evaluate_at_threshold(normal_phis, attack_phis, tau)
            marker = " <- optimal (F2)" if abs(tau - best_tau) < 0.001 else ""
            print(f"{tau:>10.4f} {r['fpr']:>8.4f} {r['tpr']:>8.4f} {r['precision']:>8.4f} {r['f1']:>8.4f}{marker}")
    else:
        print(f"\nNo attack file found. Using percentile-based tau.")
        # Default: set τ to P1 of normal Phi (1% FPR ceiling)
        best_tau = percentile(normal_sorted, 1)
        engine.tau = best_tau
        print(f"  tau set to P1 of normal Phi: {best_tau:.6f}")

    # Save
    if args.save:
        engine.save(args.model)
        print(f"\ntau = {engine.tau:.4f} saved to {args.model}")
    else:
        print(f"\nTo apply, re-run with --save flag.")


if __name__ == "__main__":
    main()
