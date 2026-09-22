"""Step 1: Preprocess the flAWS CloudTrail dataset.

Loads the raw CSV, converts rows to CloudTrail-style events,
groups by session, and writes a preprocessed JSON file for
fast reloading during training and testing.

Usage:
    python pipeline/preprocess.py [--max-rows 100000] [--output data/flaws_preprocessed.json]
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.utils import (
    load_flaws_csv, group_by_session, compute_stats,
    print_header, print_table, DATASET_PATH,
)


def main():
    parser = argparse.ArgumentParser(description="Preprocess flAWS CloudTrail CSV")
    parser.add_argument("--input", default=DATASET_PATH, help="Path to CSV")
    parser.add_argument("--output", default="data/flaws_preprocessed.json",
                        help="Output path for preprocessed JSON")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max rows to load (None = all 1.9M)")
    parser.add_argument("--stats-only", action="store_true",
                        help="Print stats without saving preprocessed file")
    args = parser.parse_args()

    print_header("SCAPE Pipeline: Step 1 - Preprocessing")
    print(f"  Input:    {args.input}")
    print(f"  Max rows: {args.max_rows or 'ALL'}")

    # Load and convert
    t0 = time.time()
    print("\nLoading CSV and converting to CloudTrail events...")
    events = load_flaws_csv(args.input, max_rows=args.max_rows)
    t_load = time.time() - t0
    print(f"  Loaded {len(events):,} events in {t_load:.1f}s")

    # Statistics
    print_header("Dataset Statistics")
    stats = compute_stats(events)
    print(f"  Total events:     {stats['total_events']:,}")
    print(f"  Unique actions:   {stats['unique_actions']}")
    print(f"  Unique sessions:  {stats['unique_sessions']}")
    print(f"  Unique sources:   {stats['unique_sources']}")
    print(f"  Error events:     {stats['error_events']:,} "
          f"({100 * stats['error_events'] / max(1, stats['total_events']):.1f}%)")

    print("\n  Top 20 Actions:")
    print_table(
        ["Action", "Count", "Pct"],
        [[a, f"{c:,}", f"{100*c/stats['total_events']:.2f}%"]
         for a, c in stats["top_actions"]],
        [45, 12, 8],
    )

    print("\n  Top 10 Event Sources:")
    print_table(
        ["Source", "Count"],
        [[s, f"{c:,}"] for s, c in stats["top_sources"]],
        [40, 12],
    )

    # Group by session
    sessions = group_by_session(events)
    session_sizes = sorted([len(v) for v in sessions.values()], reverse=True)
    print(f"\n  Sessions: {len(sessions)}")
    print(f"  Largest session:  {session_sizes[0]:,} events")
    print(f"  Median session:   {session_sizes[len(session_sizes)//2]:,} events")
    print(f"  Smallest session: {session_sizes[-1]} events")

    if args.stats_only:
        print("\n[STATS ONLY] No output file written.")
        return

    # Save preprocessed data
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    t0 = time.time()
    print(f"\nSaving preprocessed data to {args.output}...")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "source": "flAWS CloudTrail Dataset (Kaggle)",
                "total_events": len(events),
                "unique_actions": stats["unique_actions"],
                "unique_sessions": stats["unique_sessions"],
            },
            "events": events,
        }, f)
    size_mb = os.path.getsize(args.output) / (1024 * 1024)
    t_save = time.time() - t0
    print(f"  Saved {size_mb:.1f} MB in {t_save:.1f}s")

    print_header("Preprocessing Complete")


if __name__ == "__main__":
    main()
