"""SCAPE Full Pipeline: Train on ALL normal data, test on ALL data.

Combines every data file in the data/ tree:
  TRAINING (normal behaviour):
    - data/normal_traffic.json           (300 synthetic events)
    - data/test_normal.json              (90 synthetic events)
    - data/logs/my_cloudtrail_raw.json   (2062 real CloudTrail events)
    - data/logs/my_cloudtrail_scape.json (2020 real CloudTrail events)

  TESTING (anomalous / mixed):
    - data/test_anomalous.json           (61 synthetic attack events)
    - data/logs/attack_logs.json         (5 manual attack events)
    - data/logs/real_logs.json           (6 real anomalous events)
    - data/logs/flaws_sample.json        (1,939,207 flAWS recon events)

Usage:
    python pipeline/full_pipeline.py
    python pipeline/full_pipeline.py --skip-flaws          # skip the 1.9M flAWS set
    python pipeline/full_pipeline.py --flaws-limit 100000  # only first 100K flAWS events
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.scape_engine import SCAPEEngine


# ======================================================================
# Data loading helpers
# ======================================================================
def load_json(path):
    """Load a JSON file, returning a flat list of event dicts."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("Records", data.get("records", data.get("events", [data])))
    return []


def load_all_normal(base="data"):
    """Load all normal/baseline data files."""
    sources = {
        "normal_traffic":     os.path.join(base, "normal_traffic.json"),
        "test_normal":        os.path.join(base, "test_normal.json"),
        "my_cloudtrail_raw":  os.path.join(base, "logs", "my_cloudtrail_raw.json"),
        "my_cloudtrail_scape": os.path.join(base, "logs", "my_cloudtrail_scape.json"),
    }
    all_events = []
    summary = {}
    for name, path in sources.items():
        if os.path.exists(path):
            events = load_json(path)
            summary[name] = len(events)
            all_events.extend(events)
        else:
            summary[name] = "NOT FOUND"
    return all_events, summary


def load_all_attack(base="data", skip_flaws=False, flaws_limit=None):
    """Load all attack/anomalous data files."""
    sources = {
        "test_anomalous": os.path.join(base, "test_anomalous.json"),
        "attack_logs":    os.path.join(base, "logs", "attack_logs.json"),
        "real_logs":      os.path.join(base, "logs", "real_logs.json"),
    }
    all_events = []
    summary = {}
    for name, path in sources.items():
        if os.path.exists(path):
            events = load_json(path)
            summary[name] = len(events)
            all_events.extend(events)
        else:
            summary[name] = "NOT FOUND"

    # flAWS (optional, large)
    flaws_path = os.path.join(base, "logs", "flaws_sample.json")
    if not skip_flaws and os.path.exists(flaws_path):
        flaws = load_json(flaws_path)
        if flaws_limit:
            flaws = flaws[:flaws_limit]
        summary["flaws_sample"] = len(flaws)
        all_events.extend(flaws)
    elif skip_flaws:
        summary["flaws_sample"] = "SKIPPED"
    else:
        summary["flaws_sample"] = "NOT FOUND"

    return all_events, summary


# ======================================================================
# Printing
# ======================================================================
def header(title):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


# ======================================================================
# Main
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="SCAPE Full Pipeline: train on ALL normal, test on ALL data")
    parser.add_argument("--skip-flaws", action="store_true",
                        help="Skip the 1.9M flAWS dataset during testing")
    parser.add_argument("--flaws-limit", type=int, default=None,
                        help="Cap flAWS events (e.g. 100000)")
    parser.add_argument("--model-out", default="models/full_pipeline_engine.json",
                        help="Output model path")
    parser.add_argument("--results-json", default="results/full_pipeline_results.json")
    parser.add_argument("--results-txt", default="results/full_pipeline_results.txt")
    args = parser.parse_args()

    # ==================================================================
    # PHASE 1: LOAD ALL DATA
    # ==================================================================
    header("PHASE 1: Loading All Data")

    normal_events, normal_summary = load_all_normal()
    print("  Normal / Training data:")
    for name, count in normal_summary.items():
        print(f"    {name:30s}  {count}")
    print(f"    {'TOTAL':30s}  {len(normal_events)}")

    attack_events, attack_summary = load_all_attack(
        skip_flaws=args.skip_flaws, flaws_limit=args.flaws_limit)
    print("\n  Attack / Test data:")
    for name, count in attack_summary.items():
        print(f"    {name:30s}  {count}")
    print(f"    {'TOTAL':30s}  {len(attack_events)}")

    # ==================================================================
    # PHASE 2: TRAIN
    # ==================================================================
    header("PHASE 2: Training SCAPE Engine on ALL Normal Data")

    engine = SCAPEEngine()
    t0 = time.time()
    engine.train_from_logs(normal_events)
    t_train = time.time() - t0

    print(f"  Training time:       {t_train:.2f}s")
    print(f"  Total events:        {engine.total_events:,}")
    print(f"  Action vocabulary:   {len(engine.action_vocabulary)}")
    print(f"  Unique sessions:     {len(engine.seen_sessions)}")
    print(f"  Transition pairs:    {len(engine.transition_counts)}")
    print(f"  Resource bindings:   {sum(len(v) for v in engine.resource_sets.values())}")
    print(f"  Timing stats:        {len(engine.timing_stats)} actions")

    # ==================================================================
    # PHASE 3: CALIBRATE TAU
    # ==================================================================
    header("PHASE 3: Calibrating Threshold (tau)")

    # Use the last 30% of normal data + all small attack files for calibration
    split = int(len(normal_events) * 0.7)
    cal_normal = normal_events[split:]

    # Small attack files only (not flAWS) for calibration
    cal_attack, _ = load_all_attack(skip_flaws=True)

    cal_events = cal_normal + cal_attack
    cal_labels = [False] * len(cal_normal) + [True] * len(cal_attack)

    if cal_attack:
        tau = engine.calibrate(cal_events, cal_labels)
        print(f"  Calibration set:  {len(cal_normal)} normal + {len(cal_attack)} attack")
        print(f"  Calibrated tau:   {tau:.6f}")
    else:
        tau = engine.tau
        print(f"  No attack data for calibration, using default tau: {tau:.4f}")

    # Save model
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    engine.save(args.model_out)
    model_kb = os.path.getsize(args.model_out) / 1024
    print(f"  Model saved:      {args.model_out} ({model_kb:.1f} KB)")

    # ==================================================================
    # PHASE 4: TEST ON NORMAL DATA (FPR check)
    # ==================================================================
    header("PHASE 4: Testing on Normal Data (False Positive Rate)")

    fp = 0
    normal_phis = []
    prev_action = None
    prev_ts = None

    for ev in normal_events:
        result = engine.evaluate_event(prev_action, ev, prev_timestamp=prev_ts)
        normal_phis.append(result["phi"])
        if result["decision"] == "BLOCK":
            fp += 1
        prev_action = ev.get("eventName")
        if ev.get("eventTime"):
            try:
                prev_ts = engine._parse_time(ev["eventTime"])
            except Exception:
                prev_ts = None

    fpr = 100 * fp / max(1, len(normal_events))
    avg_normal_phi = sum(normal_phis) / max(1, len(normal_phis))
    print(f"  Normal events tested:  {len(normal_events):,}")
    print(f"  False Positives:       {fp} ({fpr:.2f}%)")
    print(f"  Avg Phi (normal):      {avg_normal_phi:.4f}")

    # ==================================================================
    # PHASE 5: TEST ON ATTACK DATA
    # ==================================================================
    header("PHASE 5: Testing on Attack Data (Detection Rate)")

    t0 = time.time()
    tp = 0
    attack_phis = []
    anomalous_actions = Counter()
    anomalous_by_source = defaultdict(lambda: {"total": 0, "blocked": 0})
    violation_counts = Counter()
    sample_detections = []
    prev_action = None
    prev_ts = None
    batch = 200000

    for i, ev in enumerate(attack_events):
        result = engine.evaluate_event(prev_action, ev, prev_timestamp=prev_ts)
        phi = result["phi"]
        attack_phis.append(phi)
        source_file = "unknown"
        if i < (attack_summary.get("test_anomalous", 0) if isinstance(attack_summary.get("test_anomalous"), int) else 0):
            source_file = "test_anomalous"
        elif i < sum(v for v in attack_summary.values() if isinstance(v, int)) - (attack_summary.get("flaws_sample", 0) if isinstance(attack_summary.get("flaws_sample"), int) else 0):
            source_file = "small_attack_files"
        else:
            source_file = "flaws_sample"

        if result["decision"] == "BLOCK":
            tp += 1
            action = ev.get("eventName", "Unknown")
            anomalous_actions[action] += 1
            for v in result.get("violations", []):
                violation_counts[v] += 1
            if len(sample_detections) < 30:
                sample_detections.append({
                    "action": action,
                    "phi": round(phi, 6),
                    "violations": result.get("violations", []),
                    "time": ev.get("eventTime", ""),
                })

        prev_action = ev.get("eventName")
        if ev.get("eventTime"):
            try:
                prev_ts = engine._parse_time(ev["eventTime"])
            except Exception:
                prev_ts = None

        if (i + 1) % batch == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            pct = 100 * tp / (i + 1)
            print(f"  [{i+1:>12,} / {len(attack_events):,}] "
                  f"{rate:,.0f} ev/s | BLOCK: {tp:,} ({pct:.1f}%)")

    elapsed = time.time() - t0
    tpr = 100 * tp / max(1, len(attack_events))
    avg_attack_phi = sum(attack_phis) / max(1, len(attack_phis)) if attack_phis else 0

    print(f"\n  Attack events tested:  {len(attack_events):,}")
    print(f"  True Positives:        {tp:,} ({tpr:.2f}%)")
    print(f"  Missed:                {len(attack_events) - tp:,}")
    print(f"  Avg Phi (attack):      {avg_attack_phi:.6f}")
    print(f"  Throughput:            {len(attack_events) / max(0.001, elapsed):,.0f} events/sec")

    # ==================================================================
    # PHASE 6: RESULTS
    # ==================================================================
    header("PHASE 6: Final Results Summary")

    print(f"  Model:           {args.model_out}")
    print(f"  Tau:             {engine.tau:.6f}")
    print()
    print(f"  TRAINING DATA:   {len(normal_events):,} events "
          f"({len(engine.action_vocabulary)} unique actions)")
    print(f"  NORMAL TEST:     FPR = {fpr:.2f}% ({fp}/{len(normal_events)})")
    print(f"  ATTACK TEST:     TPR = {tpr:.2f}% ({tp}/{len(attack_events)})")
    print()

    # Phi distribution
    phi_all = normal_phis + attack_phis
    phi_buckets = Counter()
    for p in phi_all:
        bucket = f"{min(int(p * 10), 9) / 10:.1f}-{min(int(p * 10) + 1, 10) / 10:.1f}"
        phi_buckets[bucket] += 1

    print("  Phi Distribution (all events):")
    for bucket in sorted(phi_buckets.keys()):
        count = phi_buckets[bucket]
        bar = "#" * min(50, max(1, int(50 * count / max(phi_buckets.values()))))
        print(f"    {bucket}: {count:>12,}  {bar}")

    print()
    print("  Top 20 Anomalous Actions:")
    for a, c in anomalous_actions.most_common(20):
        print(f"    {a:45s} {c:>10,}")

    print()
    print("  Violation Dimension Breakdown:")
    total_v = sum(violation_counts.values())
    for d, c in violation_counts.most_common():
        print(f"    {d}: {c:>12,}  ({100*c/max(1,total_v):.1f}%)")

    # Save JSON results
    results = {
        "metadata": {
            "model": args.model_out,
            "tau": engine.tau,
            "training_sources": normal_summary,
            "testing_sources": attack_summary,
        },
        "training": {
            "total_events": len(normal_events),
            "vocabulary_size": len(engine.action_vocabulary),
            "unique_sessions": len(engine.seen_sessions),
            "transition_pairs": len(engine.transition_counts),
        },
        "normal_test": {
            "total_events": len(normal_events),
            "false_positives": fp,
            "fpr_percent": round(fpr, 4),
            "avg_phi": round(avg_normal_phi, 6),
        },
        "attack_test": {
            "total_events": len(attack_events),
            "true_positives": tp,
            "tpr_percent": round(tpr, 4),
            "avg_phi": round(avg_attack_phi, 6),
        },
        "phi_distribution": dict(sorted(phi_buckets.items())),
        "top_anomalous_actions": [
            {"action": a, "count": c} for a, c in anomalous_actions.most_common(50)
        ],
        "violation_breakdown": dict(violation_counts.most_common()),
        "sample_detections": sample_detections,
    }

    os.makedirs(os.path.dirname(args.results_json), exist_ok=True)
    with open(args.results_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  JSON:  {args.results_json}")

    # Save text report
    lines = [
        "=" * 70,
        "SCAPE Full Pipeline Results",
        "=" * 70,
        f"Model:              {args.model_out}",
        f"Threshold (tau):    {engine.tau:.6f}",
        "",
        "TRAINING DATA:",
    ]
    for name, count in normal_summary.items():
        lines.append(f"  {name:30s}  {count}")
    lines.append(f"  {'TOTAL':30s}  {len(normal_events)}")
    lines.append("")
    lines.append("TESTING DATA:")
    for name, count in attack_summary.items():
        lines.append(f"  {name:30s}  {count}")
    lines.append(f"  {'TOTAL':30s}  {len(attack_events)}")
    lines.append("")
    lines.append(f"FALSE POSITIVE RATE:  {fpr:.2f}% ({fp}/{len(normal_events)})")
    lines.append(f"TRUE POSITIVE RATE:   {tpr:.2f}% ({tp}/{len(attack_events)})")
    lines.append(f"Avg Phi (normal):     {avg_normal_phi:.6f}")
    lines.append(f"Avg Phi (attack):     {avg_attack_phi:.6f}")
    lines.append("")
    lines.append("TOP ANOMALOUS ACTIONS:")
    for a, c in anomalous_actions.most_common(30):
        lines.append(f"  {a:45s} {c:>10,}")
    lines.append("")
    lines.append("VIOLATION DIMENSIONS:")
    for d, c in violation_counts.most_common():
        lines.append(f"  {d}: {c:,}")

    with open(args.results_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  TXT:   {args.results_txt}")

    header("PIPELINE COMPLETE")


if __name__ == "__main__":
    main()
