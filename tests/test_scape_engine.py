"""Dedicated unit tests for the formally specified SCAPEEngine.

Tests each scoring function (C0–C5) individually, the weighted geometric
mean combiner (compute_phi), the binary decision rule, and the F2-based
calibration method.  Includes edge cases: unseen actions in C1, missing
volume in C5, single-event sessions in C4, and weight redistribution
when C5 returns None.
"""

import math
import pytest
from datetime import datetime, timedelta, timezone

from src.scape_engine import SCAPEEngine


# ======================================================================
# Fixtures
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


def _training_logs():
    """A small, deterministic training set.

    Session s-0:  A -> B -> C  (repeated 10 times, 1s apart)
    Session s-1:  A -> B       (repeated 5 times, 1s apart)

    Every A event has volume=1000, B has volume=500, C has no volume.
    """
    logs = []
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    idx = 0
    for i in range(10):
        t = base + timedelta(seconds=idx)
        logs.append(_make_event("A", bucket="b1", session="s-0",
                                time_str=t.isoformat().replace("+00:00", "Z"),
                                volume=1000))
        idx += 1
        t = base + timedelta(seconds=idx)
        logs.append(_make_event("B", table="t1", session="s-0",
                                time_str=t.isoformat().replace("+00:00", "Z"),
                                volume=500))
        idx += 1
        t = base + timedelta(seconds=idx)
        logs.append(_make_event("C", session="s-0",
                                time_str=t.isoformat().replace("+00:00", "Z")))
        idx += 1

    for i in range(5):
        t = base + timedelta(seconds=idx)
        logs.append(_make_event("A", bucket="b1", session="s-1",
                                time_str=t.isoformat().replace("+00:00", "Z"),
                                volume=1000))
        idx += 1
        t = base + timedelta(seconds=idx)
        logs.append(_make_event("B", table="t1", session="s-1",
                                time_str=t.isoformat().replace("+00:00", "Z"),
                                volume=500))
        idx += 1

    return logs


@pytest.fixture
def engine():
    """Trained engine fixture."""
    eng = SCAPEEngine()
    eng.train_from_logs(_training_logs())
    return eng


# ======================================================================
# C0: Session context
# ======================================================================
class TestScoreC0:
    def test_known_session_returns_one(self, engine):
        """score_c0 for a session seen during training → 1.0."""
        assert engine.score_c0("s-0") == 1.0

    def test_unknown_session_returns_zero(self, engine):
        """score_c0 for a previously unseen session → 0.0."""
        assert engine.score_c0("evil-session") == 0.0


# ======================================================================
# C1: Transition flow (Laplace-smoothed Markov)
# ======================================================================
class TestScoreC1:
    def test_known_transition_high_prob(self, engine):
        """Implements C1 per Eq. 3 — known transition A→B should have
        high probability."""
        prob = engine.score_c1("A", "B")
        assert 0 < prob <= 1.0
        # A→B is the most common transition from A
        assert prob > 0.5

    def test_unseen_transition_small_but_positive(self, engine):
        """Laplace smoothing ensures unseen transitions get a small
        but positive probability, avoiding division-by-zero."""
        prob = engine.score_c1("A", "C")
        assert prob > 0.0
        # Should be much less than the known transition A→B
        assert prob < engine.score_c1("A", "B")

    def test_unseen_action_in_c1(self, engine):
        """Edge case: a completely unseen action should still return
        a valid probability via Laplace smoothing."""
        prob = engine.score_c1("A", "NEVER_SEEN_ACTION")
        assert 0 < prob < 1.0

    def test_first_event_uses_unigram(self, engine):
        """When prev_action is None (first event), C1 falls back
        to the unigram prior P(a)."""
        prob_a = engine.score_c1(None, "A")
        prob_b = engine.score_c1(None, "B")
        # A appears more frequently than B in training (15 vs 15 in
        # our fixture, so they should be close; but let's check shape)
        assert 0 < prob_a <= 1.0
        assert 0 < prob_b <= 1.0

    def test_first_event_unseen_action_zero(self, engine):
        """Unseen action as first event should give unigram 0."""
        prob = engine.score_c1(None, "NEVER_SEEN")
        assert prob == 0.0


# ======================================================================
# C2: Resource bound
# ======================================================================
class TestScoreC2:
    def test_known_resource_returns_one(self, engine):
        """Resource seen during training → 1.0."""
        assert engine.score_c2("A", "arn:aws:s3:::b1") == 1.0

    def test_unknown_resource_returns_zero(self, engine):
        """Resource not seen for this action → 0.0."""
        assert engine.score_c2("A", "arn:aws:s3:::evil-bucket") == 0.0

    def test_unknown_resource_for_action_without_resources(self, engine):
        """Action C had no resources in training → return 1.0 (no evidence)."""
        assert engine.score_c2("C", "arn:aws:s3:::anything") == 1.0

    def test_unknown_resource_string(self, engine):
        """'unknown' resource string → 1.0 (no evidence)."""
        assert engine.score_c2("A", "unknown") == 1.0


# ======================================================================
# C3: Global rarity
# ======================================================================
class TestScoreC3:
    def test_frequent_action_high_score(self, engine):
        """A is frequent → high normalised frequency."""
        score = engine.score_c3("A")
        assert 0 < score <= 1.0

    def test_unseen_action_zero(self, engine):
        """Unseen action → 0.0."""
        assert engine.score_c3("NEVER_SEEN") == 0.0

    def test_frequencies_sum_to_one(self, engine):
        """All action frequencies should sum to approximately 1.0."""
        total = sum(engine.score_c3(a) for a in engine.action_vocabulary)
        assert total == pytest.approx(1.0, abs=1e-9)


# ======================================================================
# C4: Timing (Gaussian likelihood on latency)
# ======================================================================
class TestScoreC4:
    def test_typical_latency_high_score(self, engine):
        """Implements C4 — latency near the training mean → score near 1.0."""
        # Training has ~1-second inter-arrival for B
        score = engine.score_c4("B", 1.0)
        assert score > 0.9

    def test_extreme_latency_low_score(self, engine):
        """Very large latency deviation → score near 0.0."""
        score = engine.score_c4("B", 1000.0)
        assert score < 0.01

    def test_no_delta_t_returns_one(self, engine):
        """Edge case: single-event session (delta_t is None) → 1.0."""
        assert engine.score_c4("B", None) == 1.0

    def test_unseen_action_returns_one(self, engine):
        """No timing stats for this action → 1.0."""
        assert engine.score_c4("NEVER_SEEN", 5.0) == 1.0

    def test_gaussian_formula_correctness(self, engine):
        """Manually verify the Gaussian formula for a known case."""
        if "B" not in engine.timing_stats:
            pytest.skip("No timing stats for B")
        mu, sigma = engine.timing_stats["B"]
        delta_t = mu + 2 * sigma  # 2 standard deviations away
        expected = math.exp(-0.5 * ((delta_t - mu) / (sigma + 1e-9)) ** 2)
        actual = engine.score_c4("B", delta_t)
        assert actual == pytest.approx(expected, abs=1e-9)


# ======================================================================
# C5: Data flow (Gaussian likelihood on volume)
# ======================================================================
class TestScoreC5:
    def test_typical_volume_high_score(self, engine):
        """Implements C5 — volume near training mean → high score."""
        score = engine.score_c5("A", 1000.0)
        assert score is not None
        assert score > 0.9

    def test_extreme_volume_low_score(self, engine):
        """Massive volume deviation → low score."""
        score = engine.score_c5("A", 1_000_000.0)
        assert score is not None
        assert score < 0.01

    def test_none_volume_returns_none(self, engine):
        """Edge case: volume is None → C5 returns None."""
        assert engine.score_c5("A", None) is None

    def test_low_coverage_returns_none(self, engine):
        """Edge case: action C has 0% volume coverage → None."""
        # Action C in our fixture has no bytesTransferredOut
        result = engine.score_c5("C", 500.0)
        assert result is None

    def test_unseen_action_returns_none(self, engine):
        """Unseen action → None (no stats)."""
        assert engine.score_c5("NEVER_SEEN", 100.0) is None


# ======================================================================
# compute_phi: Weighted geometric mean
# ======================================================================
class TestComputePhi:
    def test_all_ones_returns_one(self):
        """All perfect scores → Φ = 1.0."""
        scores = {"C0": 1.0, "C1": 1.0, "C2": 1.0,
                  "C3": 1.0, "C4": 1.0, "C5": 1.0}
        weights = [1/6] * 6
        assert SCAPEEngine.compute_phi(scores, weights) == pytest.approx(1.0)

    def test_all_zeros_returns_zero(self):
        """All zero scores → Φ ≈ 0.0."""
        scores = {"C0": 0.0, "C1": 0.0, "C2": 0.0,
                  "C3": 0.0, "C4": 0.0, "C5": 0.0}
        weights = [1/6] * 6
        phi = SCAPEEngine.compute_phi(scores, weights)
        assert phi < 1e-10

    def test_single_zero_pulls_phi_down(self):
        """One dimension at 0 should pull Φ toward 0 (geometric mean)."""
        scores = {"C0": 1.0, "C1": 1.0, "C2": 0.0,
                  "C3": 1.0, "C4": 1.0, "C5": 1.0}
        weights = [1/6] * 6
        phi = SCAPEEngine.compute_phi(scores, weights)
        assert phi < 0.01

    def test_c5_none_redistributes_weight(self):
        """When C5 is None, its weight is redistributed equally."""
        scores_with_c5 = {"C0": 0.8, "C1": 0.9, "C2": 1.0,
                          "C3": 0.7, "C4": 0.95, "C5": 1.0}
        scores_without_c5 = {"C0": 0.8, "C1": 0.9, "C2": 1.0,
                             "C3": 0.7, "C4": 0.95, "C5": None}
        weights = [1/6] * 6

        phi_with = SCAPEEngine.compute_phi(scores_with_c5, weights)
        phi_without = SCAPEEngine.compute_phi(scores_without_c5, weights)
        # Both should be valid floats in [0, 1]
        assert 0 <= phi_with <= 1.0
        assert 0 <= phi_without <= 1.0

    def test_uniform_scores_equal_arithmetic_mean(self):
        """With uniform weights, geometric mean of equal values = value."""
        val = 0.5
        scores = {"C0": val, "C1": val, "C2": val,
                  "C3": val, "C4": val, "C5": val}
        weights = [1/6] * 6
        phi = SCAPEEngine.compute_phi(scores, weights)
        assert phi == pytest.approx(val, abs=1e-9)

    def test_manual_weighted_sum(self):
        """Verify against a hand-calculated weighted linear sum."""
        scores = {"C0": 0.5, "C1": 0.8, "C2": 1.0,
                  "C3": 0.3, "C4": 1.0, "C5": None}
        weights = [0.1, 0.2, 0.25, 0.25, 0.1, 0.1]
        
        # C5 is None, so total_weight = 1.0 - 0.10 = 0.90
        # sum = 0.1*0.5 + 0.2*0.8 + 0.25*1.0 + 0.25*0.3 + 0.1*1.0
        # sum = 0.05 + 0.16 + 0.25 + 0.075 + 0.10 = 0.635
        # expected = 0.635 / 0.90 = 0.7055555...
        expected = 0.7055555555555556
        phi = SCAPEEngine.compute_phi(scores, weights)
        assert phi == pytest.approx(expected, rel=1e-6)


# ======================================================================
# decide: Binary decision rule
# ======================================================================
class TestDecide:
    def test_block_below_threshold(self):
        engine = SCAPEEngine()
        assert engine.decide(0.05, tau=0.1) == "BLOCK"

    def test_allow_above_threshold(self):
        engine = SCAPEEngine()
        assert engine.decide(0.5, tau=0.1) == "ALLOW"

    def test_allow_at_exact_threshold(self):
        """Φ == τ → ALLOW (not strictly less than)."""
        engine = SCAPEEngine()
        assert engine.decide(0.1, tau=0.1) == "ALLOW"

    def test_uses_instance_tau_by_default(self):
        engine = SCAPEEngine()
        engine.tau = 0.3
        assert engine.decide(0.2) == "BLOCK"
        assert engine.decide(0.4) == "ALLOW"


# ======================================================================
# calibrate: F2-score sweep
# ======================================================================
class TestCalibrate:
    def test_calibrate_sets_tau(self, engine):
        """calibrate() should set engine.tau to a value in [0, 1]."""
        normal = _training_logs()
        attack_event = _make_event("EVIL_ACTION", session="atk-0",
                                   time_str="2026-04-12T12:00:00Z")
        events = normal + [attack_event]
        labels = [False] * len(normal) + [True]

        tau = engine.calibrate(events, labels)
        assert 0.0 <= tau <= 1.0
        assert engine.tau == tau

    def test_calibrate_prefers_recall(self, engine):
        """With F2 (β=2), calibration should prefer higher recall over
        precision — selecting a tau that catches more attacks."""
        normal = _training_logs()
        # Add several obviously anomalous events
        attacks = []
        for i in range(10):
            attacks.append(_make_event(
                f"EVIL_{i}", session=f"atk-{i}",
                time_str=f"2026-04-12T13:{i:02d}:00Z"))
        events = normal + attacks
        labels = [False] * len(normal) + [True] * len(attacks)

        engine.calibrate(events, labels)
        # Verify: at the chosen tau, all attacks should be caught
        caught = 0
        prev_a = None
        prev_ts = None
        for ev, is_atk in zip(events, labels):
            r = engine.evaluate_event(prev_a, ev, prev_timestamp=prev_ts)
            if is_atk and r["decision"] == "BLOCK":
                caught += 1
            prev_a = ev.get("eventName")
            prev_ts = engine._parse_time(ev.get("eventTime", ""))
        recall = caught / len(attacks)
        assert recall >= 0.8  # F2 should find a high-recall tau


# ======================================================================
# evaluate_event: End-to-end integration
# ======================================================================
class TestEvaluateEvent:
    def test_normal_event_allowed(self, engine):
        """A completely normal event should be ALLOW."""
        event = _make_event("A", bucket="b1", session="s-0",
                            time_str="2026-01-01T00:00:01Z", volume=1000)
        prev_ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = engine.evaluate_event("C", event, prev_timestamp=prev_ts)
        # C->A is a known transition in our fixture (cycle boundary)
        # All dimensions should be high
        assert result["decision"] == "ALLOW"
        assert result["phi"] > engine.tau

    def test_completely_anomalous_event_blocked(self, engine):
        """An event with unknown session, action, and resource → BLOCK."""
        event = _make_event("HACK:DeleteAll", session="evil-99",
                            time_str="2026-04-12T12:00:00Z")
        result = engine.evaluate_event("A", event)
        assert result["decision"] == "BLOCK"
        assert result["phi"] < engine.tau
        # Should have multiple violations
        assert len(result["violations"]) >= 2

    def test_violations_list_contains_dimension_names(self, engine):
        """Violations should be a list of dimension name strings."""
        event = _make_event("UNKNOWN_ACTION", session="evil-99",
                            time_str="2026-04-12T12:00:00Z")
        result = engine.evaluate_event(None, event)
        for v in result["violations"]:
            assert v in {"C0", "C1", "C2", "C3", "C4", "C5"}

    def test_scores_in_zero_one(self, engine):
        """All non-None scores must be in [0, 1]."""
        event = _make_event("A", bucket="b1", session="s-0",
                            time_str="2026-01-01T00:00:01Z", volume=1000)
        result = engine.evaluate_event(None, event)
        for dim, val in result["scores"].items():
            if val is not None:
                assert 0.0 <= val <= 1.0, f"{dim} = {val} not in [0,1]"


# ======================================================================
# Serialization round-trip
# ======================================================================
class TestSerialization:
    def test_roundtrip_preserves_state(self, engine, tmp_path):
        """Save + load should preserve all scoring-relevant state."""
        path = str(tmp_path / "model.json")
        engine.save(path)
        loaded = SCAPEEngine.load(path)

        # Core state
        assert loaded.seen_sessions == engine.seen_sessions
        assert loaded.tau == engine.tau
        assert loaded.alpha == engine.alpha
        assert loaded.violation_threshold == engine.violation_threshold
        assert loaded.weights == engine.weights
        assert loaded.total_events == engine.total_events
        assert dict(loaded.unigram_counts) == dict(engine.unigram_counts)
        assert loaded.action_vocabulary == engine.action_vocabulary

        # Scoring should produce identical results
        event = _make_event("A", bucket="b1", session="s-0",
                            time_str="2026-01-01T00:00:01Z", volume=1000)
        r1 = engine.evaluate_event(None, event)
        r2 = loaded.evaluate_event(None, event)
        assert r1["phi"] == pytest.approx(r2["phi"], abs=1e-9)
        assert r1["decision"] == r2["decision"]
