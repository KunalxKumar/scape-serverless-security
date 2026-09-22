"""Train SCAPE on your own CloudTrail-derived SCAPE logs."""

import argparse
import json
import os

from src.scape_engine import SCAPEEngine
from src.tau_calibrator import TauCalibrator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_scape_events(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return data.get("Records", [])
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported log format: expected a JSON object or array.")


def main():
    parser = argparse.ArgumentParser(description="Train SCAPE engine or recalibrate it.")
    parser.add_argument("--recalibrate", action="store_true", help="Recalibrate tau using rolling logs instead of retraining.")
    args = parser.parse_args()

    models_dir = os.path.join(BASE_DIR, "models")
    model_path = os.path.join(models_dir, "my_engine.json")

    if args.recalibrate:
        if not os.path.exists(model_path):
            print(f"Error: No trained model found at {model_path} to recalibrate.")
            raise SystemExit(1)
            
        print("Recalibrating model threshold...")
        engine = SCAPEEngine.load(model_path)
        calibrator = TauCalibrator(os.path.join(BASE_DIR, "data", "logs", "phi_log.jsonl"))
        try:
            new_tau = calibrator.recalibrate(lookback_days=30)
            engine.tau = new_tau
            engine.save(model_path)
            print(f"Model successfully recalibrated! New tau: {new_tau:.4f}")
        except FileNotFoundError:
            print("No phi log found. You must run the engine in production to generate logs first.")
        except Exception as e:
            print(f"Recalibration failed: {e}")
        return

    log_path = os.path.join(BASE_DIR, "data", "logs", "my_cloudtrail_scape.json")
    if not os.path.exists(log_path):
        print(f"Error: {log_path} not found. Run cloudtrail_adapter.py first.")
        raise SystemExit(1)

    my_logs = load_scape_events(log_path)
    print(f"Loaded {len(my_logs)} events from your CloudTrail logs.")

    engine = SCAPEEngine()
    engine.train_from_logs(my_logs)
    # Calibrate tau to the 1st percentile of normal training scores (1% FPR cap)
    phis = []
    prev_a = None
    prev_ts = None
    for ev in my_logs:
        r = engine.evaluate_event(prev_a, ev, prev_timestamp=prev_ts)
        phis.append(r["phi"])
        prev_a = ev.get("eventName")
        prev_ts = engine._parse_time(ev.get("eventTime", ""))
    if phis:
        phis.sort()
        idx = int(len(phis) * 0.01)
        engine.tau = phis[max(0, min(idx, len(phis)-1))]
    
    print(f"Training and calibration complete (tau: {engine.tau:.4f})!")

    os.makedirs(models_dir, exist_ok=True)
    engine.save(model_path)

    print(f"Model saved to {model_path}")
    print("\n--- Training Statistics ---")
    print(f"Total events: {len(my_logs)}")
    print(f"Unique actions: {len(engine.global_action_counts)}")
    print(f"Valid entry actions: {len(engine.valid_entry_actions)}")
    print(f"Known session prefixes: {len(engine.known_session_prefixes)}")
    print(f"Transitions learned: {len(engine.allowed_transitions)}")
    print(f"Actions with timing stats: {len(engine.timing_stats)}")
    print(f"Actions with data flow stats: {len(engine.data_flow_stats)}")
    print(f"Calibrated Threshold (tau): {engine.tau:.4f}")


if __name__ == "__main__":
    main()
