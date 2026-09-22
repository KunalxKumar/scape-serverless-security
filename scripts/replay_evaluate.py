"""Stage 2: Replay historical CloudTrail logs against the new engine.

Evaluates every event in a parsed log file, logs Phi scores, reports
the False Positive Rate (FPR), and validates session memory behaviour.

Usage:
    python scripts/replay_evaluate.py \\
        --model models/my_engine.json \\
        --events data/logs/parsed_replay.json \\
        --phi-log results/replay_phi_log.jsonl
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine
from src.tau_calibrator import TauCalibrator
from src.session_tracker import SessionTracker


def load_events(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("Records", [])
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported log format: expected JSON object or array.")


def main():
    parser = argparse.ArgumentParser(description="Replay-evaluate historical events.")
    parser.add_argument("--model", required=True, help="Path to trained engine JSON.")
    parser.add_argument("--events", required=True, help="Path to parsed events JSON.")
    parser.add_argument("--phi-log", default=None, help="Path to write phi JSONL log.")
    parser.add_argument("--label", default="normal",
                        help="Traffic label to embed in phi log (normal|attack).")
    args = parser.parse_args()

    # Load model
    if not os.path.exists(args.model):
        print(f"[!] Model not found: {args.model}")
        sys.exit(1)
    engine = SCAPEEngine.load(args.model)
    print(f"Loaded model from {args.model}  (tau={engine.tau:.4f})")

    # Load events
    if not os.path.exists(args.events):
        print(f"[!] Events file not found: {args.events}")
        sys.exit(1)
    events = load_events(args.events)
    print(f"Loaded {len(events)} events for replay.")

    # Optional phi log setup
    calibrator = None
    if args.phi_log:
        os.makedirs(os.path.dirname(os.path.abspath(args.phi_log)), exist_ok=True)
        calibrator = TauCalibrator(args.phi_log)

    # Session tracker for realistic context
    tracker = SessionTracker()

    # Counters
    total = 0
    blocked = 0
    decisions = defaultdict(int)
    phi_scores = []
    initial_session_count = len(engine.seen_sessions)

    print("\nReplaying events...")
    for event in events:
        ctx = tracker.get_context(event)
        result = engine.evaluate_event(
            prev_action=ctx["prev_action"],
            curr_event=event,
            prev_timestamp=ctx["prev_timestamp"],
            session_age_seconds=ctx.get("session_age_seconds", 0.0),
        )

        phi = result["phi"]
        decision = result["decision"]
        phi_scores.append(phi)
        decisions[decision] += 1
        total += 1

        if decision == "BLOCK":
            blocked += 1

        if calibrator:
            calibrator.log_phi(phi, label=args.label)

    # Session memory validation (Fix 6)
    final_session_count = len(engine.seen_sessions)

    # --- Report ---
    fpr = blocked / total if total > 0 else 0.0
    avg_phi = sum(phi_scores) / len(phi_scores) if phi_scores else 0.0
    phi_above_tau = sum(1 for p in phi_scores if p >= engine.tau)

    print("\n" + "=" * 60)
    print("REPLAY EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Total events:          {total}")
    print(f"  ALLOW decisions:       {decisions['ALLOW']}")
    print(f"  BLOCK decisions:       {blocked}")
    print(f"  False Positive Rate:   {fpr:.2%}  (target <= 1%)")
    print(f"  Avg Phi score:         {avg_phi:.4f}  (tau={engine.tau:.4f})")
    print(f"  Events above tau:      {phi_above_tau}/{total} ({phi_above_tau/total:.1%})")
    print(f"  Session cache size:    {final_session_count} (was {initial_session_count})")
    print("=" * 60)

    if fpr > 0.01:
        print(f"\n  [!] FPR {fpr:.2%} exceeds 1% target.")
        print("      Run: python train_my_logs.py --recalibrate")
    else:
        print(f"\n  [OK] FPR is within the 1% target. Engine looks healthy!")

    if args.phi_log:
        print(f"\n  Phi scores logged to: {args.phi_log}")


if __name__ == "__main__":
    main()
