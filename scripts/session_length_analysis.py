"""Session Length Stability Analysis for SCAPE.

Generates a plot showing how Phi stabilises as session length increases,
demonstrating the effect of the confidence weighting mechanism.

The script replays a normal traffic log through the engine, tracking
Phi at each event index, then overlays the confidence-weighted version.

Usage:
    python scripts/session_length_analysis.py

Output:
    results/session_length_stability.png
"""

import json
import os
import sys

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import matplotlib.pyplot as plt
import numpy as np
from src.scape_engine import SCAPEEngine


def load_logs(path):
    """Load CloudTrail-style log records from JSON."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("Records", data.get("records", [data]))
    return data


def extract_sessions(events):
    """Group events by sessionId."""
    sessions = {}
    for ev in events:
        sid = ev.get("sessionId", "default")
        if sid not in sessions:
            sessions[sid] = []
        sessions[sid].append(ev)
    return sessions


def main():
    # Paths
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", "my_engine.json")
    data_paths = [
        os.path.join(os.path.dirname(__file__), "..", "data", "normal_traffic.json"),
        os.path.join(os.path.dirname(__file__), "..", "data", "logs", "normal_traffic.json"),
    ]

    data_path = None
    for p in data_paths:
        if os.path.exists(p):
            data_path = p
            break

    if data_path is None:
        print("ERROR: Could not find normal_traffic.json in data/ or data/logs/")
        sys.exit(1)

    if not os.path.exists(model_path):
        print(f"ERROR: Model not found at {model_path}")
        sys.exit(1)

    print(f"Loading model from {model_path}")
    engine = SCAPEEngine.load(model_path)

    print(f"Loading logs from {data_path}")
    events = load_logs(data_path)
    print(f"  Loaded {len(events)} events")

    sessions = extract_sessions(events)
    print(f"  Found {len(sessions)} sessions")

    # Find the longest session for the primary plot
    longest_sid = max(sessions, key=lambda k: len(sessions[k]))
    longest_events = sessions[longest_sid]
    print(f"  Longest session: {longest_sid} ({len(longest_events)} events)")

    # Score without confidence weighting (min_events_for_trust=0 -> no adjustment)
    raw_phis = []
    weighted_phis = []
    prev_action = None
    prev_ts = None

    for i, ev in enumerate(longest_events):
        # Raw phi (session_event_count >= min_events -> no adjustment)
        engine.min_events_for_trust = 0
        result_raw = engine.evaluate_event(
            prev_action, ev, prev_timestamp=prev_ts,
            session_event_count=999
        )
        raw_phis.append(result_raw["phi"])

        # Weighted phi (with confidence scaling)
        engine.min_events_for_trust = 10
        result_weighted = engine.evaluate_event(
            prev_action, ev, prev_timestamp=prev_ts,
            session_event_count=i + 1
        )
        weighted_phis.append(result_weighted["phi"])

        prev_action = ev.get("eventName")
        prev_ts = engine._parse_time(ev.get("eventTime", ""))

    # Plot
    fig, ax = plt.subplots(figsize=(12, 6))
    x = range(1, len(raw_phis) + 1)

    ax.plot(x, raw_phis, 'o-', color='#e74c3c', alpha=0.6,
            markersize=4, label='Raw Phi (no confidence weighting)')
    ax.plot(x, weighted_phis, 's-', color='#2ecc71', alpha=0.8,
            markersize=4, label='Weighted Phi (confidence-adjusted)')
    ax.axhline(y=engine.tau, color='#3498db', linestyle='--', linewidth=2,
               label=f'tau = {engine.tau:.2f} (decision threshold)')
    ax.axvline(x=10, color='#95a5a6', linestyle=':', alpha=0.7,
               label='min_events_for_trust = 10')

    ax.set_xlabel("Event Number in Session", fontsize=12)
    ax.set_ylabel("Phi (Anomaly Score)", fontsize=12)
    ax.set_title(f"Phi Stability as Session Length Increases\n"
                 f"Session: {longest_sid} ({len(longest_events)} events)",
                 fontsize=14)
    ax.legend(loc='lower right', fontsize=10)
    ax.set_ylim(-0.05, 1.1)
    ax.grid(True, alpha=0.3)

    # Shade the "low confidence" region
    ax.axvspan(0, 10, alpha=0.08, color='orange', label='_nolegend_')
    ax.text(5, 0.02, 'Low Confidence\nRegion', ha='center',
            fontsize=9, color='#d35400', alpha=0.8)

    plt.tight_layout()

    out_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "session_length_stability.png")
    plt.savefig(out_path, dpi=150)
    print(f"\nPlot saved to {out_path}")

    # Print summary statistics
    print("\n--- Summary ---")
    print(f"  Events in session: {len(raw_phis)}")
    if raw_phis:
        print(f"  Raw Phi   - first 5: {[f'{p:.3f}' for p in raw_phis[:5]]}")
        print(f"  Weighted  - first 5: {[f'{p:.3f}' for p in weighted_phis[:5]]}")
        print(f"  Raw Phi   - mean:    {np.mean(raw_phis):.4f}")
        print(f"  Weighted  - mean:    {np.mean(weighted_phis):.4f}")
        print(f"  Raw Phi   - std:     {np.std(raw_phis):.4f}")
        print(f"  Weighted  - std:     {np.std(weighted_phis):.4f}")


if __name__ == "__main__":
    main()
