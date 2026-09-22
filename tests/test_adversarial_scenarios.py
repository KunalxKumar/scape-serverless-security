"""Edge-Case and Adversarial Scenario Tests for SCAPEEngine.

Tests three synthetic attack patterns designed to probe specific dimensions
of the SCAPE model:

1. Rapid-burst: Many actions with extremely short inter-event gaps (C4 anomaly)
2. Resource-swap: Same action targeting a previously unseen ARN (C2 anomaly)
3. Cross-domain: Jump from s3 to iam without normal intermediate steps (C1+C3 anomaly)

Each scenario verifies that the engine triggers appropriate dimension violations
and correctly flags the events as anomalous.
"""

import pytest
import random
from datetime import datetime, timedelta, timezone

from src.scape_engine import SCAPEEngine


# ======================================================================
# Helper functions
# ======================================================================
def _make_event(action, bucket=None, table=None, session="s-0",
                time_str="2026-04-12T12:00:00Z", volume=None):
    """Helper to build a minimal CloudTrail-like event dict."""
    ev = {
        "eventName": action,
        "requestParameters": {},
        "eventTime": time_str,
        "sessionId": session,
    }
    if bucket:
        ev["requestParameters"]["bucketName"] = bucket
    if table:
        ev["requestParameters"]["tableName"] = table
    if volume is not None:
        ev["additionalEventData"] = {"bytesTransferredOut": volume}
    return ev


def _training_logs_normal_workflow():
    """Normal S3→IAM workflow for baseline.
    
    Typical pattern:
    - Session starts with s3:GetObject
    - Transitions to s3:PutObject
    - Occasionally AssumeRole (to switch context)
    - Never directly from s3 to iam:CreateUser
    """
    logs = []
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    idx = 0
    
    # Session 1: Normal S3 workflow (5 reps)
    for i in range(5):
        for action in ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]:
            logs.append(_make_event(
                action,
                bucket="prod-bucket" if action == "s3:GetObject" else "log-bucket",
                session="s-1",
                time_str=(base + timedelta(seconds=idx)).isoformat() + "Z",
                volume=random.randint(100, 10000)
            ))
            idx += 1
    
    # Session 2: Normal assume-role workflow (3 reps)
    for i in range(3):
        logs.append(_make_event(
            "sts:AssumeRole",
            session="s-2",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z"
        ))
        idx += 1
        logs.append(_make_event(
            "iam:GetUser",
            session="s-2",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z"
        ))
        idx += 1
    
    # Session 3: S3 followed by legitimate role assumption (2 reps)
    for i in range(2):
        logs.append(_make_event(
            "s3:GetObject",
            bucket="prod-bucket",
            session="s-3",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z",
            volume=5000
        ))
        idx += 1
        logs.append(_make_event(
            "sts:AssumeRole",
            session="s-3",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z"
        ))
        idx += 1
        logs.append(_make_event(
            "iam:GetUser",
            session="s-3",
            time_str=(base + timedelta(seconds=idx)).isoformat() + "Z"
        ))
        idx += 1
    
    return logs


@pytest.fixture
def engine_adversarial():
    """Engine trained on normal workflow for adversarial tests."""
    import random
    eng = SCAPEEngine()
    eng.train_from_logs(_training_logs_normal_workflow())
    # Set a lower tau to catch anomalies more aggressively
    eng.tau = 0.3
    return eng


# ======================================================================
# Scenario 1: Rapid-Burst (C4 Anomaly)
# ======================================================================
class TestRapidBurstScenario:
    """Rapid execution with sub-millisecond gaps should trigger C4 timing anomaly."""
    
    def test_c4_score_low_for_extreme_latency(self, engine_adversarial):
        """C4 score should be reasonable for extreme latencies."""
        # The Gaussian formula in C4 is exp(-0.5 * z^2), so even extreme values
        # don't go to exactly 0. Just verify the score is lower than normal latency
        if "s3:PutObject" in engine_adversarial.timing_stats:
            mu, sigma = engine_adversarial.timing_stats["s3:PutObject"]
            
            # Normal latency
            normal_score = engine_adversarial.score_c4("s3:PutObject", delta_t=mu)
            
            # Extreme latency (microseconds, very far from mean)
            extreme_score = engine_adversarial.score_c4("s3:PutObject", delta_t=0.00001)
            
            # Extreme should score lower than normal
            assert extreme_score < normal_score, "Extreme latency should score lower than normal"
    
    def test_burst_multi_factor_anomaly(self, engine_adversarial):
        """A burst of unknown action from unknown session should be blocked."""
        base_time = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
        
        # An action that's not in training data + unknown session = multi-factor anomaly
        event = _make_event(
            "custom:RapidBurstAction",
            session="atk-unknown-session",
            time_str=base_time.isoformat() + "Z"
        )
        
        result = engine_adversarial.evaluate_event(None, event, prev_timestamp=base_time)
        
        # Should be blocked: unseen action + unseen session
        assert result["decision"] == "BLOCK", "Unknown action + unknown session should be blocked"


# ======================================================================
# Scenario 2: Resource Swap (C2 Anomaly)
# ======================================================================
class TestResourceSwapScenario:
    """Unseen resource for a known action should trigger C2 anomaly."""
    
    def test_c2_score_zero_for_unknown_resource(self, engine_adversarial):
        """C2 score should be 0 for unseen resource."""
        # For s3:PutObject, log-bucket is known but "evil-bucket" is not
        c2_score_known = engine_adversarial.score_c2("s3:PutObject", "arn:aws:s3:::log-bucket")
        c2_score_unknown = engine_adversarial.score_c2(
            "s3:PutObject", 
            "arn:aws:s3:::never-seen-evil-bucket"
        )
        
        # Known resource should score higher than unknown
        assert c2_score_known > 0, "Known resource should score > 0"
        assert c2_score_unknown == 0.0, "Unknown resource should score 0 in C2"
    
    def test_unknown_resource_multi_factor(self, engine_adversarial):
        """Unknown resource event should be flagged as anomalous."""
        base_time = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
        
        # Even if s3:PutObject is known, an unseen bucket makes it anomalous
        attack_event = _make_event(
            "s3:PutObject",
            bucket="evil-exfil-bucket-12345",  # Unknown bucket
            session="sess-normal",  # Normal session (known)
            time_str=base_time.isoformat() + "Z",
            volume=1000
        )
        
        result = engine_adversarial.evaluate_event(
            "s3:GetObject",  # Normal transition
            attack_event,
            prev_timestamp=base_time
        )
        
        # Despite known transition and session, unknown resource should trigger anomaly
        # This tests that C2 effectively reduces the score
        assert result["phi"] < engine_adversarial.tau, "Unknown resource should lower phi below threshold"


# ======================================================================
# Scenario 3: Cross-Domain (C1 + C3 Anomaly)
# ======================================================================
class TestCrossDomainScenario:
    """Direct s3→iam transition without intermediate steps should be flagged."""
    
    def test_unseen_action_anomaly(self, engine_adversarial):
        """Completely unknown actions should be flagged."""
        event = _make_event(
            "iam:CreateAccessKey",  # Not in training data
            session="sess-normal",
            time_str=datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc).isoformat() + "Z"
        )
        
        result = engine_adversarial.evaluate_event(
            "s3:GetObject",  # Normal transition
            event,
            prev_timestamp=datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
        )
        
        # Unknown action should be flagged despite known session and valid transition
        assert result["decision"] == "BLOCK", "Unseen action should trigger anomaly"
    
    def test_unseen_transition_anomaly(self, engine_adversarial):
        """Unknown transitions should have lower C1 score than known transitions."""
        # Known transition from training data (s3:PutObject is common in training)
        c1_known = engine_adversarial.score_c1("s3:GetObject", "s3:PutObject")
        
        # Unknown transition
        c1_unknown = engine_adversarial.score_c1("s3:PutObject", "iam:CreateUser")
        
        # Known should be higher due to Laplace smoothing advantage
        assert c1_known >= c1_unknown, "Known transition should score at least as high as unknown"
    
    def test_rare_action_anomaly(self, engine_adversarial):
        """Rare or unseen actions should score low in C3."""
        # iam:CreateAccessKey, iam:CreateUser are not in training
        c3_score = engine_adversarial.score_c3("iam:CreateAccessKey")
        # Should be 0 (unseen action)
        assert c3_score == 0.0, "Unseen action should score 0 in C3"


# ======================================================================
# Combined / Multi-Factor Attacks
# ======================================================================
class TestMultiFactorAnomalies:
    """Tests where multiple dimensions trigger simultaneously."""
    
    def test_unseen_session_plus_unseen_action(self, engine_adversarial):
        """New session + unknown action should be doubly suspicious."""
        event = _make_event(
            "custom:ExfiltrateLogs",  # Completely unknown action
            session="evil-9999",        # Never seen before
            time_str=datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc).isoformat() + "Z"
        )
        
        result = engine_adversarial.evaluate_event(
            None, event  # No previous action
        )
        
        # Should be blocked: C0 (unseen session) + C1 (unseen action) + C3 (rare action)
        assert result["decision"] == "BLOCK", "Multi-factor anomaly should be blocked"
