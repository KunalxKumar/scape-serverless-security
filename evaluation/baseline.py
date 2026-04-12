import json
import sys
import os

# Set up paths so this runs from anywhere
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')

class StaticIAMBaseline:
    def __init__(self, allowed_actions):
        self.allowed_actions = set(allowed_actions)

    def evaluate_event(self, prev_action, event):
        action = event['eventName']
        if action in self.allowed_actions:
            return {"decision": "ALLOW", "anomaly_score": 0.0}
        else:
            return {"decision": "BLOCK", "anomaly_score": 10.0}

def evaluate_baseline(baseline, logs, expected_attack_labels):
    prev = None
    decisions = []
    for event in logs:
        result = baseline.evaluate_event(prev, event)
        decisions.append(result['decision'])
        prev = event['eventName']

    tp = fp = tn = fn = 0
    for pred, is_attack in zip(decisions, expected_attack_labels):
        pred_block = pred == "BLOCK"
        if pred_block and is_attack: tp += 1
        elif pred_block and not is_attack: fp += 1
        elif not pred_block and not is_attack: tn += 1
        elif not pred_block and is_attack: fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn}

if __name__ == "__main__":
    with open(os.path.join(DATA_DIR, "normal_traffic.json")) as f:
        normal_logs = json.load(f)
        
    allowed = set()
    for log in normal_logs:
        allowed.add(log['eventName'])

    baseline = StaticIAMBaseline(allowed)

    test_normal = json.load(open(os.path.join(DATA_DIR, "test_normal.json")))
    test_anom = json.load(open(os.path.join(DATA_DIR, "test_anomalous.json")))

    normal_res = evaluate_baseline(baseline, test_normal, [False]*len(test_normal))
    attack_res = evaluate_baseline(baseline, test_anom, [True]*len(test_anom))

    print("=== Static IAM Baseline ===")
    print(f"Normal Set - Precision: {normal_res['precision']:.3f}, Recall: {normal_res['recall']:.3f}, F1: {normal_res['f1']:.3f}")
    print(f"Attack Set - Precision: {attack_res['precision']:.3f}, Recall: {attack_res['recall']:.3f}, F1: {attack_res['f1']:.3f}")
