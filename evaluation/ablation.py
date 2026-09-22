"""Ablation study for SCAPEEngine by selectively disabling check dimensions.

Each disabled dimension is set to 1.0 (perfectly normal), so it contributes
no anomaly signal to the combined weighted geometric mean Φ.
"""

import json
import sys
import os
from copy import deepcopy

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def load_logs(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
        if isinstance(data, dict) and "Records" in data:
            return data["Records"]
        return data

class AblationEngine(SCAPEEngine):
    """Wrapper that disables specific checks by setting their scores to 1.0.

    Uses the engine's built-in ``_evaluate_event_internal`` method which
    accepts a set of disabled check names.
    """

    def __init__(self, disabled_checks=None):
        super().__init__()
        self.disabled_checks = disabled_checks or set()

    def evaluate_event(self, prev_action, curr_event,
                       session_history=None, prev_timestamp=None):
        """Score event with disabled dimensions set to 1.0 (no anomaly)."""
        return self._evaluate_event_internal(
            prev_action, curr_event, self.disabled_checks)

def evaluate_ablation(engine, logs, expected_labels):
    prev_action = None
    decisions = []
    for event in logs:
        res = engine.evaluate_event(prev_action, event)
        decisions.append(res['decision'])
        prev_action = event.get('eventName', 'Unknown')

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

    base_engine = SCAPEEngine()
    base_engine.train_from_logs(train_logs)

    configs = [
        ("Full SCAPE (C0-C5)", set()),
        ("Without C0 (Session)", {"C0"}),
        ("Without C1 (Transition)", {"C1"}),
        ("Without C2 (Resource)", {"C2"}),
        ("Without C3 (Rarity)", {"C3"}),
        ("Without C4 (Timing)", {"C4"}),
        ("Without C5 (Data Flow)", {"C5"}),
        ("Static IAM Baseline", {"C0","C1","C3","C4","C5"}), # Only C2 remains
    ]

    print("\n=== ABLATION STUDY ===")
    print(f"{'Configuration':<30} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print("-" * 65)

    for name, disabled in configs:
        engine = AblationEngine(disabled_checks=disabled)
        # Copy trained state from base engine
        engine.seen_sessions = deepcopy(base_engine.seen_sessions)
        engine.allowed_transitions = deepcopy(base_engine.allowed_transitions)
        engine.allowed_resources = deepcopy(base_engine.allowed_resources)
        engine.resource_sets = deepcopy(base_engine.resource_sets)
        engine.transition_counts = deepcopy(base_engine.transition_counts)
        engine.resource_counts = deepcopy(base_engine.resource_counts)
        engine.action_counts = deepcopy(base_engine.action_counts)
        engine.unigram_counts = deepcopy(base_engine.unigram_counts)
        engine.total_events = base_engine.total_events
        engine.action_vocabulary = deepcopy(base_engine.action_vocabulary)
        engine.global_action_counts = deepcopy(base_engine.global_action_counts)
        engine.total_global_events = base_engine.total_global_events
        engine.valid_entry_actions = deepcopy(base_engine.valid_entry_actions)
        engine.known_session_prefixes = deepcopy(base_engine.known_session_prefixes)
        engine.timing_stats = deepcopy(base_engine.timing_stats)
        engine.data_flow_stats = deepcopy(base_engine.data_flow_stats)
        engine.data_flow_coverage = deepcopy(base_engine.data_flow_coverage)

        # We assume all events in test_anomalous are attacks for this study
        res = evaluate_ablation(engine, attack_logs, [True] * len(attack_logs))
        print(f"{name:<30} {res['precision']:<10.3f} {res['recall']:<10.3f} {res['f1']:<10.3f}")
