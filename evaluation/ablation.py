import json
import sys
import os

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def load_logs(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def evaluate_ablation(engine, logs, expected_labels, disable_checks):
    """Run evaluation with specific checks disabled."""
    decisions = []
    prev = None
    for event in logs:
        res = engine._evaluate_event_internal(prev, event, disable_checks)
        decisions.append(res['decision'])
        prev = event['eventName']
    
    tp = fp = tn = fn = 0
    for pred, is_attack in zip(decisions, expected_labels):
        pred_anomaly = pred != "ALLOW"
        if pred_anomaly and is_attack: tp += 1
        elif pred_anomaly and not is_attack: fp += 1
        elif not pred_anomaly and not is_attack: tn += 1
        elif not pred_anomaly and is_attack: fn += 1
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}

if __name__ == "__main__":
    train_path = os.path.join(PROJECT_ROOT, "data", "normal_traffic.json")
    attack_path = os.path.join(PROJECT_ROOT, "data", "test_anomalous.json")
    
    train_logs = load_logs(train_path)
    attack_logs = load_logs(attack_path)
    
    engine = SCAPEEngine()
    engine.train_from_logs(train_logs)
    
    configs = [
        ("Full SCAPE (C0-C5)", set()),
        ("Without C0 (Session)", {"C0"}),
        ("Without C1 (Transition)", {"C1"}),
        ("Without C2 (Resource)", {"C2"}),
        ("Without C3 (Rarity)", {"C3"}),
        ("Static IAM Baseline", {"C0","C1","C3","C4","C5"})
    ]
    
    print("\n=== ABLATION STUDY ===")
    print(f"{'Configuration':<30} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print("-" * 65)
    for name, disabled in configs:
        # Assuming all events in test_anomalous are attacks for the study
        # In reality, evaluate.py uses [True] * len(test_anomalous)
        res = evaluate_ablation(engine, attack_logs, [True]*len(attack_logs), disabled)
        print(f"{name:<30} {res['precision']:<10.3f} {res['recall']:<10.3f} {res['f1']:<10.3f}")
