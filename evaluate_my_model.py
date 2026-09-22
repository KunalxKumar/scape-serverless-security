"""Evaluate a trained SCAPE model against attack and flAWS datasets."""

import argparse
import json
import os
from typing import Any, Dict, List

from src.scape_engine import SCAPEEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_records(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return data.get("Records", [])
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported log format: expected a JSON object or array.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a trained SCAPE model against attack and flAWS datasets.")
    parser.add_argument("--attack-limit", type=int, default=0, help="Limit the number of synthetic attack events to evaluate (0 = all).")
    parser.add_argument("--flaws-limit", type=int, default=1000, help="Limit the number of flAWS records to evaluate (0 = all).")
    return parser.parse_args()


def test_dataset(engine: SCAPEEngine, records: List[Dict[str, Any]], name: str):
    prev_action = None
    prev_timestamp = None
    detections = 0
    false_negatives = 0

    for i, event in enumerate(records):
        result = engine.evaluate_event(prev_action, event, prev_timestamp=prev_timestamp)
        if result["decision"] != "ALLOW":
            detections += 1
        else:
            false_negatives += 1
            print(f"  Missed: {event.get('eventName', 'Unknown')} (index {i})")

        prev_action = event.get("eventName")
        prev_timestamp = engine._parse_time(event.get("eventTime", ""))

    print(f"{name}: {detections}/{len(records)} detected ({detections / len(records) * 100:.1f}%)")
    return detections, false_negatives


def main():
    args = parse_args()

    model_path = os.path.join(BASE_DIR, "models", "my_engine.json")
    if not os.path.exists(model_path):
        print(f"Error: {model_path} not found. Run train_my_logs.py first.")
        raise SystemExit(1)

    engine = SCAPEEngine.load(model_path)
    print("Model loaded.")

    attack_path = os.path.join(BASE_DIR, "data", "test_anomalous.json")
    if os.path.exists(attack_path):
        attack_logs = load_records(attack_path)
        if args.attack_limit > 0:
            attack_logs = attack_logs[: args.attack_limit]
        print(f"\n--- Testing on {len(attack_logs)} synthetic attack events ---")
        test_dataset(engine, attack_logs, "Synthetic attack detection")
    else:
        print(f"Attack file not found: {attack_path}")

    flaws_path = os.path.join(BASE_DIR, "data", "logs", "flaws_sample.json")
    if os.path.exists(flaws_path):
        flaws_records = load_records(flaws_path)
        flaws_limit = args.flaws_limit if args.flaws_limit > 0 else len(flaws_records)
        chosen = flaws_records[:flaws_limit]
        print(f"\n--- Testing on flAWS dataset (first {len(chosen)} events) ---")
        test_dataset(engine, chosen, "flAWS detection")
    else:
        print(f"Attack file not found: {flaws_path}")


if __name__ == "__main__":
    main()
