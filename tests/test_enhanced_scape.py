"""Unit tests for the formally specified SCAPEEngine.

Tests cover: training state, individual scoring functions (C0–C5),
the combined Φ score, decision logic, and public API shape.
"""

import pytest
import math
import os
import sys
from datetime import datetime, timedelta, timezone
from src.scape_engine import SCAPEEngine


# ----------------------------------------------------------------------
# Sample log generators
# ----------------------------------------------------------------------
def generate_normal_logs():
    """Create a set of normal training logs with timing and data flow."""
    logs = []
    base_time = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
    session_prefix = "normal-session"
    for i in range(20):
        session = f"{session_prefix}-{i % 3}"
        t = base_time + timedelta(seconds=i * 6)
        # Sequence: s3:GetObject -> dynamodb:PutItem -> logs:PutLogEvents
        ev1 = {
            "eventName": "s3:GetObject",
            "requestParameters": {"bucketName": "my-bucket"},
            "eventTime": t.isoformat().replace('+00:00', 'Z'),
            "sessionId": session,
            "additionalEventData": {"bytesTransferredOut": 1024}
        }
        ev2 = {
            "eventName": "dynamodb:PutItem",
            "requestParameters": {"tableName": "my-table"},
            "eventTime": (t + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'),
            "sessionId": session,
            "additionalEventData": {"bytesTransferredOut": 512}
        }
        ev3 = {
            "eventName": "logs:PutLogEvents",
            "requestParameters": {"logGroupName": "/aws/lambda/myfunc"},
            "eventTime": (t + timedelta(seconds=2)).isoformat().replace('+00:00', 'Z'),
            "sessionId": session,
            "additionalEventData": {"bytesTransferredOut": 256}
        }
        logs.extend([ev1, ev2, ev3])
    return logs

def generate_attack_event():
    """Return a single anomalous event (rare action, wrong transition)."""
    return {
        "eventName": "iam:CreateUser",
        "requestParameters": {"userName": "backdoor"},
        "eventTime": datetime(2026, 4, 12, 13, 0, 0,
                              tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z'),
        "sessionId": "attacker-0",
        "additionalEventData": {"bytesTransferredOut": 100}
    }

# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------
class TestSCAPEEngine:
    @pytest.fixture
    def engine(self):
        eng = SCAPEEngine()
        eng.train_from_logs(generate_normal_logs())
        return eng

    def test_training_sets_sessions(self, engine):
        """C0: training should record all session IDs."""
        assert "normal-session-0" in engine.seen_sessions
        assert "normal-session-1" in engine.seen_sessions
        assert "normal-session-2" in engine.seen_sessions

    def test_training_sets_entry_actions(self, engine):
        """Legacy: valid entry actions should be recorded."""
        assert "s3:GetObject" in engine.valid_entry_actions
        assert "normal-session" in engine.known_session_prefixes

    def test_training_builds_transitions(self, engine):
        assert "dynamodb:PutItem" in engine.allowed_transitions["s3:GetObject"]
        assert "logs:PutLogEvents" in engine.allowed_transitions["dynamodb:PutItem"]

    def test_training_builds_resources(self, engine):
        assert "arn:aws:s3:::my-bucket" in engine.resource_sets["s3:GetObject"]
        assert "arn:aws:dynamodb:us-east-1:000000000000:table/my-table" in engine.resource_sets["dynamodb:PutItem"]

    def test_training_timing_stats(self, engine):
        assert "dynamodb:PutItem" in engine.timing_stats
        mean, std = engine.timing_stats["dynamodb:PutItem"]
        assert std >= 0

    def test_training_data_flow_stats(self, engine):
        assert "s3:GetObject" in engine.data_flow_stats
        mean, std = engine.data_flow_stats["s3:GetObject"]
        assert mean == pytest.approx(1024.0, rel=0.1)

    def test_training_data_flow_coverage(self, engine):
        """C5 coverage should be 100% since all events have volume."""
        assert engine.data_flow_coverage["s3:GetObject"] == pytest.approx(1.0)

    def test_evaluate_normal_sequence(self, engine):
        """Normal sequence should yield ALLOW with high Φ."""
        prev_action = "s3:GetObject"
        t0 = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
        event = {
            "eventName": "dynamodb:PutItem",
            "requestParameters": {"tableName": "my-table"},
            "eventTime": (t0 + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'),
            "sessionId": "normal-session-1",
            "additionalEventData": {"bytesTransferredOut": 512}
        }
        result = engine.evaluate_event(prev_action, event,
                                       prev_timestamp=t0)
        assert result["decision"] == "ALLOW"
        assert result["phi"] > engine.tau
        assert len(result["violations"]) == 0

    def test_return_dict_shape(self, engine):
        """evaluate_event() must return all required keys."""
        event = {
            "eventName": "s3:GetObject",
            "requestParameters": {"bucketName": "my-bucket"},
            "eventTime": "2026-04-12T12:00:00Z",
            "sessionId": "normal-session-0",
        }
        result = engine.evaluate_event(None, event)
        assert "decision" in result
        assert "phi" in result
        assert "scores" in result
        assert "violations" in result
        # Backward compat aliases
        assert "anomaly_score" in result
        assert "surprise_breakdown" in result
        # Scores dict has C0–C5
        for dim in ["C0", "C1", "C2", "C3", "C4"]:
            assert dim in result["scores"]
        assert "C5" in result["scores"]

    def test_evaluate_attack_transition(self, engine):
        """Bad transition should produce BLOCK."""
        prev_action = "s3:GetObject"
        event = generate_attack_event()
        result = engine.evaluate_event(prev_action, event)
        assert result["decision"] == "BLOCK"
        assert "C1" in result["violations"] or "C3" in result["violations"]

    def test_evaluate_attack_resource(self, engine):
        """Known action but unknown resource should flag C2."""
        prev_action = "s3:GetObject"
        event = {
            "eventName": "s3:GetObject",
            "requestParameters": {"bucketName": "evil-bucket"},
            "eventTime": "2026-04-12T12:00:05Z",
            "sessionId": "normal-session-1",
        }
        result = engine.evaluate_event(prev_action, event)
        assert result["scores"]["C2"] == 0.0
        assert "C2" in result["violations"]

    def test_evaluate_attack_rarity(self, engine):
        """iam:CreateUser is unseen in training, so C3 should be 0.0."""
        event = generate_attack_event()
        result = engine.evaluate_event(None, event)
        assert result["scores"]["C3"] == 0.0
        assert "C3" in result["violations"]

    def test_decision_thresholds(self, engine):
        """Test that decision respects tau."""
        engine.tau = 0.5
        event = {
            "eventName": "s3:GetObject",
            "requestParameters": {"bucketName": "evil-bucket"},
            "eventTime": "2026-04-12T12:00:10Z",
            "sessionId": "normal-session-1",
        }
        result = engine.evaluate_event("s3:GetObject", event)
        phi = result["phi"]
        if phi < 0.5:
            assert result["decision"] == "BLOCK"
        else:
            assert result["decision"] == "ALLOW"


if __name__ == "__main__":
    import pytest
    import sys
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.append(project_root)
    sys.exit(pytest.main([__file__]))
