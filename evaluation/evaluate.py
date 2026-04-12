import json
import sys
import os

# Add the project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def load_logs(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def evaluate(engine, logs, expected_attack_labels=None):
    """
    expected_attack_labels: list of bool same length as logs.
    If None, assume all are normal.
    """
    prev_action = None
    decisions = []
    scores = []
    for i, event in enumerate(logs):
        result = engine.evaluate_event(prev_action, event)
        decisions.append(result['decision'])
        scores.append(result['anomaly_score'])
        prev_action = event['eventName']

    if expected_attack_labels is None:
        expected_attack_labels = [False] * len(logs)

    tp = fp = tn = fn = 0
    for pred, is_attack in zip(decisions, expected_attack_labels):
        pred_anomaly = pred != "ALLOW"
        if pred_anomaly and is_attack:
            tp += 1
        elif pred_anomaly and not is_attack:
            fp += 1
        elif not pred_anomaly and not is_attack:
            tn += 1
        elif not pred_anomaly and is_attack:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    for i, (pred, is_attack) in enumerate(zip(decisions, expected_attack_labels)):
        pred_anomaly = pred != "ALLOW"
        if is_attack and not pred_anomaly:
            print(f"Missed attack at index {i}: {logs[i]}")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "decisions": decisions
    }

if __name__ == "__main__":
    # Load training data (normal only)
    train_logs = load_logs("data/normal_traffic.json")
    engine = SCAPEEngine()
    engine.train_from_logs(train_logs)

    # Evaluate on normal test set
    test_normal = load_logs("data/test_normal.json")
    normal_results = evaluate(engine, test_normal, [False]*len(test_normal))

    # Evaluate on anomalous test set
    test_anomalous = load_logs("data/test_anomalous.json")
    # Assuming the anomalous file has an "is_attack" field or we label manually
    labels = [True] * len(test_anomalous)  # Simplification
    attack_results = evaluate(engine, test_anomalous, labels)

    print("=== SCAPE Evaluation ===")
    print(f"Normal Set - Precision: {normal_results['precision']:.3f}, Recall: {normal_results['recall']:.3f}, F1: {normal_results['f1']:.3f}")
    print(f"Attack Set - Precision: {attack_results['precision']:.3f}, Recall: {attack_results['recall']:.3f}, F1: {attack_results['f1']:.3f}")
