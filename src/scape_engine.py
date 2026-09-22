"""SCAPEEngine — Structural Context-Aware Probabilistic Engine.

Formal specification
====================
Every CloudTrail event is represented as a tuple:

    e = (a, r, σ, t, v)

where *a* is the action string, *r* the resource ARN, *σ* the session ID,
*t* a Unix-epoch timestamp, and *v* an optional data-volume in bytes.

The engine evaluates six behavioural consistency dimensions (C0–C5),
each producing a score in [0, 1].  Scores are combined via a weighted
geometric mean Φ, and the final decision is BLOCK when Φ < τ.

Dependencies: standard library + numpy.
"""

import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from collections import OrderedDict
import time

class TTLCache(OrderedDict):
    def __init__(self, maxsize=50000, ttl=3600):
        super().__init__()
        self.maxsize = maxsize
        self.ttl = ttl
    def __setitem__(self, key, value):
        if len(self) >= self.maxsize:
            self.popitem(last=False)
        super().__setitem__(key, value)

# ---------------------------------------------------------------------------
# Configurable defaults via environment
# ---------------------------------------------------------------------------
_ENV_WEIGHTS = os.environ.get("SCAPE_WEIGHTS", "")
DEFAULT_WEIGHTS: List[float] = [1 / 6] * 6
if _ENV_WEIGHTS:
    try:
        DEFAULT_WEIGHTS = [float(w.strip()) for w in _ENV_WEIGHTS.split(",")]
    except (ValueError, TypeError):
        pass  # keep defaults


class SCAPEEngine:
    """Structural Context-Aware Probabilistic Engine.

    Public API
    ----------
    - ``train_from_logs(records)``   – learn normal behaviour.
    - ``evaluate_event(prev_action, curr_event, ...)`` – score a live event.
    - ``calibrate(validation_events, validation_labels)`` – set τ via F2.
    """

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------
    def __init__(self) -> None:
        """Initialise engine with default hyper-parameters.

        Hyper-parameters
        ~~~~~~~~~~~~~~~~
        * ``alpha``  – Laplace smoothing pseudo-count (Eq. 3).
        * ``tau``    – decision threshold: Φ < τ ⇒ BLOCK.
        * ``violation_threshold`` – per-dimension flag threshold.
        * ``weights`` – per-dimension weights for the geometric mean.
        """
        # Laplace smoothing parameter (Eq. 3)
        self.alpha: float = 0.01

        # Decision threshold (trained via calibrate())
        self.tau: float = 0.1

        # Per-dimension violation flag threshold
        self.violation_threshold: float = 0.2

        # Session-length confidence weighting (reduces FP on short sessions)
        self.min_events_for_trust: int = int(
            os.environ.get("SCAPE_MIN_EVENTS", "10"))
        self.confidence_power: float = float(
            os.environ.get("SCAPE_CONFIDENCE_POWER", "0.5"))

        # Hard guard: skip scoring entirely for ultra-short sessions
        self.skip_short_sessions: int = int(
            os.environ.get("SCAPE_SKIP_SHORT_SESSIONS", "0"))  # 0 = disabled

        # Dimension weights (default uniform)
        self.weights: List[float] = list(DEFAULT_WEIGHTS)

        # --- C0: Session context ---
        self.seen_sessions = TTLCache(maxsize=50_000, ttl=3600)

        # --- C1: Transition flow (Markov) ---
        self.transition_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self.action_counts: Dict[str, int] = defaultdict(int)     # row totals
        self.action_vocabulary: Set[str] = set()                  # |A|
        self.unigram_counts: Dict[str, int] = defaultdict(int)
        self.total_events: int = 0

        # --- C2: Resource bound ---
        self.resource_sets: Dict[str, Set[str]] = defaultdict(set)

        # --- C3: Global rarity ---
        self.global_action_counts: Dict[str, int] = defaultdict(int)
        self.total_global_events: int = 0

        # --- C4: Timing ---
        self.timing_data: Dict[str, List[float]] = defaultdict(list)
        self.timing_stats: Dict[str, Tuple[float, float]] = {}   # (μ, σ)

        # --- C5: Data flow ---
        self.data_flow_data: Dict[str, List[float]] = defaultdict(list)
        self.data_flow_stats: Dict[str, Tuple[float, float]] = {}
        self.data_flow_coverage: Dict[str, float] = {}           # fraction

        # --- Kept for backward compat with detector / online learning ---
        self.allowed_transitions: Dict[str, Set[str]] = defaultdict(set)
        self.allowed_resources: Dict[str, Set[str]] = defaultdict(set)
        self.valid_entry_actions: Set[str] = set()
        self.known_session_prefixes: Set[str] = set()
        self.resource_counts: Dict[Tuple[str, str], int] = defaultdict(int)

        # Legacy thresholds (kept for serialisation compat — not used in decide())
        self.threshold_alert: float = float(
            os.environ.get("SCAPE_THRESHOLD_ALERT", "2.0"))
        self.threshold_restrict: float = float(
            os.environ.get("SCAPE_THRESHOLD_RESTRICT", "6.25"))
        self.threshold_block: float = float(
            os.environ.get("SCAPE_THRESHOLD_BLOCK", "12.5"))

        # Per-action sensitivity (legacy — not used in formal scoring)
        self.action_sensitivity: Dict[str, float] = {
            "s3:GetObject": 1.0,
            "dynamodb:PutItem": 1.0,
            "logs:PutLogEvents": 0.5,
            "s3:DeleteBucket": 10.0,
            "iam:CreateUser": 10.0,
            "s3:PutObject": 1.5,
            "dynamodb:DeleteTable": 8.0,
            "lambda:UpdateFunctionCode": 9.0,
            "lambda:AddPermission": 9.0,
            "iam:AttachRolePolicy": 10.0,
            "iam:PutRolePolicy": 10.0,
            "AssumeRole": 0.3,
            "sts:AssumeRole": 0.3,
            "sts:GetCallerIdentity": 0.2,
            "sts:GetSessionToken": 0.3,
        }

        # Legacy extras kept for serialisation
        self.rarity_threshold: float = 0.0001
        self.min_rarity_count: int = 5
        self.c4_thresholds: Dict[str, float] = {}
        self.c5_thresholds: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train_from_logs(self, logs: List[Dict]) -> None:
        """Learn normal behaviour from a list of CloudTrail event dicts.

        Builds all data structures required by C0–C5:

        * **C0** — ``seen_sessions`` set.
        * **C1** — transition count matrix with row totals; unigram prior.
        * **C2** — per-action resource ARN sets.
        * **C3** — global action frequencies.
        * **C4** — per-action inter-event latency mean/std.
        * **C5** — per-action data-volume mean/std and coverage %.
        """
        session_last_action: Dict[str, str] = {}
        session_last_time: Dict[str, datetime] = {}

        # Per-action counters for C5 coverage computation
        action_total_count: Dict[str, int] = defaultdict(int)
        action_volume_count: Dict[str, int] = defaultdict(int)

        for event in logs:
            action = event.get("eventName", "Unknown")
            resource = self._extract_resource(event)
            session_id = event.get("sessionId", "default")
            timestamp = self._parse_time(event.get("eventTime", ""))
            volume = self._extract_size(event)

            # C0: record session
            self.seen_sessions[session_id] = True

            # C1: unigram counts
            self.unigram_counts[action] += 1
            self.total_events += 1
            self.action_vocabulary.add(action)

            # C3: global action counts
            self.global_action_counts[action] += 1
            self.total_global_events += 1

            # C0 legacy: entry actions & session prefixes
            if session_id not in session_last_action:
                self.valid_entry_actions.add(action)
                prefix = (session_id.rsplit("-", 1)[0]
                          if "-" in session_id else session_id)
                self.known_session_prefixes.add(prefix)

            # C1: transitions
            if session_id in session_last_action:
                prev_action = session_last_action[session_id]
                self.transition_counts[(prev_action, action)] += 1
                self.action_counts[prev_action] += 1
                self.allowed_transitions[prev_action].add(action)

                # C4: inter-arrival latency
                if session_id in session_last_time:
                    delta = (timestamp - session_last_time[session_id]
                             ).total_seconds()
                    if delta >= 0:
                        self.timing_data[action].append(delta)

            session_last_action[session_id] = action
            session_last_time[session_id] = timestamp

            # C2: resources
            if resource and resource != "unknown":
                self.resource_sets[action].add(resource)
                self.resource_counts[(action, resource)] += 1
                self.allowed_resources[action].add(resource)

            # C5: data flow volume
            action_total_count[action] += 1
            if volume is not None:
                self.data_flow_data[action].append(float(volume))
                action_volume_count[action] += 1

        # ---- Derived statistics ----

        # C4: timing (mean, std)
        for action, times in self.timing_data.items():
            if times:
                arr = np.array(times, dtype=np.float64)
                self.timing_stats[action] = (float(np.mean(arr)),
                                             float(np.std(arr)))

        # C5: data flow (mean, std, coverage)
        for action, sizes in self.data_flow_data.items():
            if sizes:
                arr = np.array(sizes, dtype=np.float64)
                self.data_flow_stats[action] = (float(np.mean(arr)),
                                                float(np.std(arr)))
            total = action_total_count.get(action, 0)
            self.data_flow_coverage[action] = (
                action_volume_count.get(action, 0) / total
                if total > 0 else 0.0
            )

        # Initialise streaming counters for incremental_update()
        self._timing_online: Dict[str, Tuple[int, float, float]] = {}
        for action, times in self.timing_data.items():
            if times:
                n = len(times)
                mean = sum(times) / n
                m2 = sum((t - mean) ** 2 for t in times)
                self._timing_online[action] = (n, mean, m2)

        self._dataflow_online: Dict[str, Tuple[int, float, float]] = {}
        for action, sizes in self.data_flow_data.items():
            if sizes:
                n = len(sizes)
                mean = sum(sizes) / n
                m2 = sum((s - mean) ** 2 for s in sizes)
                self._dataflow_online[action] = (n, mean, m2)

    # ------------------------------------------------------------------
    # Scoring functions  (each → float in [0, 1], or None for C5)
    # ------------------------------------------------------------------
    def score_c0(self, sigma: str, age_seconds: float = 0.0) -> float:
        """Implements C0 — Session-context consistency with 3-tier trust.
        """
        # Tier 1: known session — full trust
        if sigma in self.seen_sessions:
            return 1.0

        # Tier 2: matches a trusted prefix (e.g. "cognito-us-east-1:")
        if any(sigma.startswith(p) for p in self.known_session_prefixes):
            return 0.4 + 0.4 * min(1.0, age_seconds / 300) if age_seconds else 0.4

        # Tier 3: completely unknown — time-ramp from 0 -> 0.3 over 5 min
        return min(0.3, (age_seconds / 300) * 0.3) if age_seconds else 0.0

    def score_c1(self, prev_action: Optional[str],
                 curr_action: str) -> float:
        """Implements C1 per Eq. 3 — Laplace-smoothed Markov transition probability.

        .. math::

            T[i][j] = \\frac{\\text{count}(i \\to j) + \\alpha}
                           {\\text{count}(i) + \\alpha \\cdot |A|}

        If *prev_action* is ``None`` (first event in a session), the
        unigram prior P(a) = count(a) / total_events is returned instead.
        """
        if prev_action is None:
            # Unigram fallback for first event
            if self.total_events == 0:
                return 1.0  # untrained engine — assume benign
            p = self.unigram_counts.get(curr_action, 0) / self.total_events
        else:
            vocab_size = max(len(self.action_vocabulary), 1)
            count_ij = self.transition_counts.get((prev_action, curr_action), 0)
            count_i = self.action_counts.get(prev_action, 0)
            p = (count_ij + self.alpha) / (count_i + self.alpha * vocab_size)

        min_prob = 1 / max(1, self.total_events + len(self.action_vocabulary))
        min_prob = min(min_prob, 1e-9)
        # Log-map probability to [0,1]
        p = max(p, min_prob)
        normalised = (math.log(p) - math.log(min_prob)) / (0 - math.log(min_prob))
        return max(0.0, min(1.0, normalised))

    def score_c2(self, action: str, resource: str) -> float:
        """Implements C2 — Resource-bound consistency.

        Returns 1.0 if *resource* is in the training set of ARNs
        observed for *action*, 0.0 otherwise.

        If the resource is ``"unknown"`` or the action had no resources
        in training, 1.0 is returned (no evidence of anomaly).
        """
        if resource == "unknown" or action not in self.resource_sets:
            return 1.0
        return 1.0 if resource in self.resource_sets[action] else 0.0

    def score_c3(self, action: str) -> float:
        """Implements C3 — Log-normalised global action frequency.

        Maps raw frequency to [0, 1] using the same log-scale normalization
        as C1, so that legitimate actions that are common relative to the
        corpus (but not dominant) do not get over-penalized.
        """
        if self.total_global_events == 0:
            return 1.0
        count = self.global_action_counts.get(action, 0)
        if count == 0:
            return 0.0

        freq = count / self.total_global_events
        min_freq = 1.0 / self.total_global_events
        normalized = (math.log(freq) - math.log(min_freq)) / (
            0.0 - math.log(min_freq)
        )
        return max(0.0, min(1.0, normalized))

    def score_c4(self, action: str, delta_t: Optional[float]) -> float:
        """Implements C4 — Gaussian likelihood over inter-event latency.

        .. math::

            \\text{score} = \\exp\\!\\left(
                -\\frac{1}{2}\\left(\\frac{\\Delta t - \\mu_a}
                {\\sigma_a + 10^{-9}}\\right)^{\\!2}\\right)

        Returns 1.0 when no timing statistics are available or when
        *delta_t* is ``None`` (first event in session).
        """
        if delta_t is None:
            return 1.0
        if action not in self.timing_stats:
            return 1.0
        mu, sigma = self.timing_stats[action]
        z = (delta_t - mu) / (sigma + 1e-9)
        return float(math.exp(-0.5 * z * z))

    def score_c5(self, action: str,
                 volume: Optional[float]) -> Optional[float]:
        """Implements C5 — Gaussian likelihood over data volume.

        Same formula as C4, applied to bytes transferred.

        Returns ``None`` (and must be excluded from Φ) when:
        * *volume* is ``None``, **or**
        * training coverage for this action is below 80 %.
        """
        if volume is None:
            return None
        coverage = self.data_flow_coverage.get(action, 0.0)
        if coverage < 0.80:
            return None
        if action not in self.data_flow_stats:
            return None
        mu, sigma = self.data_flow_stats[action]
        z = (volume - mu) / (sigma + 1e-9)
        return float(math.exp(-0.5 * z * z))

    # ------------------------------------------------------------------
    # Combined score
    # ------------------------------------------------------------------
    @staticmethod
    def compute_phi(scores: Dict[str, Optional[float]],
                    weights: List[float]) -> float:
        """Weighted aggregation with soft C2/C3 penalty.

        A hard veto (phi = 0) can collapse scores under mixed distributions.
        This applies a bounded multiplicative penalty for low C2/C3 instead.
        """
        VETO_THRESHOLD = 0.10
        VETO_DIMS = {'C2', 'C3'}
        penalty = 1.0
        for dim in VETO_DIMS:
            score = scores.get(dim)
            if score is not None and score < VETO_THRESHOLD:
                penalty *= max(0.1, score / VETO_THRESHOLD)

        PHI_WEIGHTS = {
            'C0': 0.10,
            'C1': 0.20,
            'C2': 0.25,
            'C3': 0.25,
            'C4': 0.10,
            'C5': 0.10,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for dim, w in PHI_WEIGHTS.items():
            s = scores.get(dim)
            if s is not None:
                total_weight += w
                weighted_sum += w * s

        if total_weight == 0:
            return 1.0

        return (weighted_sum / total_weight) * penalty

    def compute_weighted_phi(self, scores: Dict[str, Optional[float]],
                             session_event_count: int) -> float:
        """Compute Phi with confidence scaling based on session length.

        For sessions shorter than ``min_events_for_trust``, the raw Phi
        is pushed toward 1.0 (ALLOW).  This prevents false positives
        on the first few events of a session where the engine has
        insufficient context to make a reliable decision.

        When ``session_event_count`` is 0 (the default for callers that
        don't track session length), confidence weighting is skipped to
        preserve backward compatibility.

        confidence = (count / min_events)^power        [0..1]
        phi_adj    = 1.0 - confidence * (1.0 - phi)    [phi..1.0]
        """
        phi = self.compute_phi(scores, self.weights)
        # session_event_count == 0 means "unspecified" — skip weighting
        if (session_event_count > 0
                and session_event_count < self.min_events_for_trust):
            confidence = (
                session_event_count / self.min_events_for_trust
            ) ** self.confidence_power
            phi = 1.0 - confidence * (1.0 - phi)
        return phi

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------
    def decide(self, phi: float, tau: Optional[float] = None) -> str:
        """Binary decision rule: BLOCK if Φ < τ, else ALLOW.

        Parameters
        ----------
        phi : float
            Combined anomaly score in [0, 1].
        tau : float, optional
            Decision threshold (defaults to ``self.tau``).
        """
        if tau is None:
            tau = self.tau
        return "BLOCK" if phi < tau else "ALLOW"

    # ------------------------------------------------------------------
    # Calibration
    # ------------------------------------------------------------------
    def calibrate(self, validation_events: List[Dict],
                  validation_labels: List[bool]) -> float:
        """Calibrate τ by maximising F2-score on a validation set.

        Sweeps τ from 0.00 to 1.00 in steps of 0.01.  For each
        candidate, events are scored and the F2-score (β = 2, weighting
        recall over precision) is computed.  The engine's ``self.tau``
        is set to the maximising value.

        Parameters
        ----------
        validation_events : list[dict]
            CloudTrail event dicts (mixed normal + attack).
        validation_labels : list[bool]
            ``True`` for attack events, ``False`` for normal.

        Returns
        -------
        float
            The selected τ value.
        """
        # Pre-compute Φ for every event
        phis: List[float] = []
        prev_action: Optional[str] = None
        prev_ts: Optional[datetime] = None
        for event in validation_events:
            result = self.evaluate_event(prev_action, event,
                                         prev_timestamp=prev_ts)
            phis.append(result["phi"])
            prev_action = event.get("eventName")
            prev_ts = self._parse_time(event.get("eventTime", ""))

        best_tau = 0.0
        best_f2 = -1.0

        for tau_int in range(0, 101):
            tau = tau_int / 100.0
            tp = fp = fn = 0
            for phi, is_attack in zip(phis, validation_labels):
                pred_anomaly = phi < tau
                if pred_anomaly and is_attack:
                    tp += 1
                elif pred_anomaly and not is_attack:
                    fp += 1
                elif not pred_anomaly and is_attack:
                    fn += 1

            beta = 2.0
            beta_sq = beta * beta
            denom = beta_sq * tp + beta_sq * fn + tp + fp
            f2 = ((1 + beta_sq) * tp / denom) if denom > 0 else 0.0

            if f2 > best_f2:
                best_f2 = f2
                best_tau = tau

        self.tau = best_tau
        return best_tau

    # ------------------------------------------------------------------
    # Online / Incremental Learning
    # ------------------------------------------------------------------
    def incremental_update(self, event: Dict,
                           session_state: Optional[Dict] = None) -> None:
        """Update the model with a single new event (online learning).

        Uses Welford's algorithm for streaming mean/variance updates.
        This avoids re-processing the entire training set.

        Args:
            event: A single CloudTrail-style event dict.
            session_state: Optional dict with 'prev_action' and 'prev_timestamp'
                           keys for session context. If None, treated as a
                           session start.
        """
        action = event.get("eventName", "Unknown")
        resource = self._extract_resource(event)
        session_id = event.get("sessionId", "default")
        timestamp = self._parse_time(event.get("eventTime", ""))
        volume = self._extract_size(event)

        prev_action = (session_state.get("prev_action")
                       if session_state else None)
        prev_timestamp = (session_state.get("prev_timestamp")
                          if session_state else None)

        # C0
        self.seen_sessions[session_id] = True

        # C1 + C3
        self.unigram_counts[action] += 1
        self.total_events += 1
        self.action_vocabulary.add(action)
        self.global_action_counts[action] += 1
        self.total_global_events += 1

        # C0 legacy
        if prev_action is None:
            self.valid_entry_actions.add(action)
            prefix = (session_id.rsplit("-", 1)[0]
                      if "-" in session_id else session_id)
            self.known_session_prefixes.add(prefix)

        # C1: transitions
        if prev_action:
            self.transition_counts[(prev_action, action)] += 1
            self.action_counts[prev_action] += 1
            self.allowed_transitions[prev_action].add(action)

        # C2: resources
        if resource and resource != "unknown":
            self.resource_sets[action].add(resource)
            self.resource_counts[(action, resource)] += 1
            self.allowed_resources[action].add(resource)

        # C4: Timing — Welford's online update
        if prev_timestamp:
            delta_t = (timestamp - prev_timestamp).total_seconds()
            if delta_t >= 0:
                if not hasattr(self, "_timing_online"):
                    self._timing_online = {}
                if action not in self._timing_online:
                    self._timing_online[action] = (0, 0.0, 0.0)
                n, mean, m2 = self._timing_online[action]
                n += 1
                d1 = delta_t - mean
                mean += d1 / n
                d2 = delta_t - mean
                m2 += d1 * d2
                self._timing_online[action] = (n, mean, m2)
                std = (math.sqrt(m2 / n)
                       if n > 1 and m2 > 0 else 1.0)
                self.timing_stats[action] = (mean, std)

        # C5: Data flow — Welford's online update
        if volume is not None and volume > 0:
            if not hasattr(self, "_dataflow_online"):
                self._dataflow_online = {}
            if action not in self._dataflow_online:
                self._dataflow_online[action] = (0, 0.0, 0.0)
            n, mean, m2 = self._dataflow_online[action]
            n += 1
            d1 = volume - mean
            mean += d1 / n
            d2 = volume - mean
            m2 += d1 * d2
            self._dataflow_online[action] = (n, mean, m2)
            std = (math.sqrt(m2 / n)
                   if n > 1 and m2 > 0 else 1.0)
            self.data_flow_stats[action] = (mean, std)

    def update_and_evaluate(self, event: Dict,
                            session_state: Optional[Dict] = None) -> Dict:
        """Evaluate an event, then update the model with it.

        This is the primary method for online deployments: score the event
        first, then incorporate it into the model for future scoring.

        Returns the same dict as evaluate_event().
        """
        prev_action = (session_state.get("prev_action")
                       if session_state else None)
        prev_timestamp = (session_state.get("prev_timestamp")
                          if session_state else None)

        # Score first (before learning this event)
        result = self.evaluate_event(prev_action, event,
                                     prev_timestamp=prev_timestamp)

        # Only learn from events that were ALLOW
        if result["decision"] == "ALLOW":
            self.incremental_update(event, session_state)

        return result

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate_event(self, prev_action: Optional[str],
                       curr_event: Dict,
                       session_history: Optional[List[str]] = None,
                       prev_timestamp: Optional[datetime] = None,
                       session_age_seconds: float = 0.0,
                       session_event_count: int = 0) -> Dict:
        """Evaluate a single event and return decision, Phi, scores, violations.

        Parameters
        ----------
        prev_action : str or None
            The preceding action in this session (None for first event).
        curr_event : dict
            CloudTrail-style event dict.
        session_history : list[str], optional
            Legacy parameter -- ignored.
        prev_timestamp : datetime, optional
            Timestamp of the preceding event (for C4 latency).
        session_age_seconds : float
            Seconds since the session was first observed (for C0 trust ramp).
        session_event_count : int
            Number of events already seen in this session (0 = first event).
            Used for confidence weighting.

        Returns
        -------
        dict
            Keys: ``decision``, ``phi``, ``scores`` (C0-C5 dict),
            ``violations`` (list of dimension names).

            Backward-compatible aliases: ``anomaly_score`` = ``phi``,
            ``surprise_breakdown`` = ``scores``.
        """
        # Hard guard: skip scoring entirely for ultra-short sessions
        if self.skip_short_sessions and session_event_count < self.skip_short_sessions:
            return {
                "decision": "ALLOW",
                "phi": 1.0,
                "scores": {},
                "violations": [],
                "skipped": True,
                "anomaly_score": 1.0,
                "surprise_breakdown": {},
            }

        action = curr_event.get("eventName", "Unknown")
        resource = self._extract_resource(curr_event)
        session_id = curr_event.get("sessionId", "default")
        timestamp = self._parse_time(curr_event.get("eventTime", ""))
        volume = self._extract_size(curr_event)

        # Compute inter-event latency
        delta_t: Optional[float] = None
        if prev_timestamp is not None:
            delta_t = (timestamp - prev_timestamp).total_seconds()

        # ---- Individual scores ----
        s_c0 = self.score_c0(session_id, session_age_seconds)
        s_c1 = self.score_c1(prev_action, action)
        s_c2 = self.score_c2(action, resource)
        s_c3 = self.score_c3(action)
        s_c4 = self.score_c4(action, delta_t)
        s_c5 = self.score_c5(action, volume)

        scores: Dict[str, Optional[float]] = {
            "C0": s_c0, "C1": s_c1, "C2": s_c2,
            "C3": s_c3, "C4": s_c4, "C5": s_c5,
        }

        # ---- Violations ----
        violations: List[str] = []
        for dim, val in scores.items():
            if val is not None and val < self.violation_threshold:
                violations.append(dim)

        # ---- Combined score (with confidence weighting) ----
        phi = self.compute_weighted_phi(scores, session_event_count)

        # ---- Decision ----
        decision = self.decide(phi)

        return {
            "decision": decision,
            "phi": phi,
            "scores": {k: v for k, v in scores.items()},
            "violations": violations,
            # Backward-compatible aliases
            "anomaly_score": phi,
            "surprise_breakdown": {k: (v if v is not None else 0.0)
                                   for k, v in scores.items()},
        }

    def _evaluate_event_internal(self, prev_action: Optional[str],
                                 curr_event: Dict,
                                 disabled_checks: Set[str]) -> Dict:
        """Evaluate with selected checks disabled (used by ablation).

        Disabled checks are set to 1.0 (perfectly normal) so they do
        not influence the combined Φ.
        """
        action = curr_event.get("eventName", "Unknown")
        resource = self._extract_resource(curr_event)
        session_id = curr_event.get("sessionId", "default")
        timestamp = self._parse_time(curr_event.get("eventTime", ""))
        volume = self._extract_size(curr_event)

        s_c0 = 1.0 if "C0" in disabled_checks else self.score_c0(session_id)
        s_c1 = (1.0 if "C1" in disabled_checks
                else self.score_c1(prev_action, action))
        s_c2 = (1.0 if "C2" in disabled_checks
                else self.score_c2(action, resource))
        s_c3 = (1.0 if "C3" in disabled_checks
                else self.score_c3(action))
        s_c4 = 1.0 if "C4" in disabled_checks else self.score_c4(action, None)
        s_c5_raw = (None if "C5" in disabled_checks
                    else self.score_c5(action, volume))

        scores: Dict[str, Optional[float]] = {
            "C0": s_c0, "C1": s_c1, "C2": s_c2,
            "C3": s_c3, "C4": s_c4, "C5": s_c5_raw,
        }

        violations = [dim for dim, val in scores.items()
                      if val is not None and val < self.violation_threshold]

        phi = self.compute_phi(scores, self.weights)
        decision = self.decide(phi)

        return {
            "decision": decision,
            "phi": phi,
            "scores": dict(scores),
            "violations": violations,
            "anomaly_score": phi,
            "surprise_breakdown": {k: (v if v is not None else 0.0)
                                   for k, v in scores.items()},
        }

    # ------------------------------------------------------------------
    # Serialization (JSON-safe, no pickle)
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state to a JSON-safe dictionary."""
        def _tuple_key_to_str(d):
            return {f"{k[0]}|{k[1]}": v for k, v in d.items()}

        def _set_dict_to_list_dict(d):
            return {k: sorted(v) for k, v in d.items()}

        return {
            "version": "3.0",
            "alpha": self.alpha,
            "tau": self.tau,
            "violation_threshold": self.violation_threshold,
            "weights": self.weights,
            "seen_sessions": sorted(self.seen_sessions.keys()),
            "allowed_transitions": _set_dict_to_list_dict(
                self.allowed_transitions),
            "allowed_resources": _set_dict_to_list_dict(
                self.allowed_resources),
            "resource_sets": _set_dict_to_list_dict(self.resource_sets),
            "transition_counts": _tuple_key_to_str(self.transition_counts),
            "resource_counts": _tuple_key_to_str(self.resource_counts),
            "action_counts": dict(self.action_counts),
            "unigram_counts": dict(self.unigram_counts),
            "total_events": self.total_events,
            "action_vocabulary": sorted(self.action_vocabulary),
            "global_action_counts": dict(self.global_action_counts),
            "total_global_events": self.total_global_events,
            "valid_entry_actions": sorted(self.valid_entry_actions),
            "known_session_prefixes": sorted(self.known_session_prefixes),
            "timing_stats": {k: list(v)
                             for k, v in self.timing_stats.items()},
            "data_flow_stats": {k: list(v)
                                for k, v in self.data_flow_stats.items()},
            "data_flow_coverage": dict(self.data_flow_coverage),
            "action_sensitivity": self.action_sensitivity,
            "threshold_alert": self.threshold_alert,
            "threshold_restrict": self.threshold_restrict,
            "threshold_block": self.threshold_block,
            "rarity_threshold": self.rarity_threshold,
            "c4_thresholds": self.c4_thresholds,
            "c5_thresholds": self.c5_thresholds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SCAPEEngine":
        """Deserialize engine state from a JSON dictionary."""
        def _str_to_tuple_key(d):
            return {tuple(k.split("|", 1)): v for k, v in d.items()}

        engine = cls()
        engine.alpha = data.get("alpha", engine.alpha)
        engine.tau = data.get("tau", engine.tau)
        engine.violation_threshold = data.get("violation_threshold",
                                              engine.violation_threshold)
        engine.weights = data.get("weights", engine.weights)
        engine.seen_sessions = TTLCache(maxsize=50_000, ttl=3600)
        for s in data.get("seen_sessions", []):
            engine.seen_sessions[s] = True
        engine.allowed_transitions = defaultdict(
            set, {k: set(v) for k, v
                  in data.get("allowed_transitions", {}).items()})
        engine.allowed_resources = defaultdict(
            set, {k: set(v) for k, v
                  in data.get("allowed_resources", {}).items()})
        engine.resource_sets = defaultdict(
            set, {k: set(v) for k, v
                  in data.get("resource_sets",
                              data.get("allowed_resources", {})).items()})
        engine.transition_counts = defaultdict(
            int, _str_to_tuple_key(data.get("transition_counts", {})))
        engine.resource_counts = defaultdict(
            int, _str_to_tuple_key(data.get("resource_counts", {})))
        engine.action_counts = defaultdict(
            int, data.get("action_counts", {}))
        engine.unigram_counts = defaultdict(
            int, data.get("unigram_counts", {}))
        engine.total_events = data.get("total_events", 0)
        engine.action_vocabulary = set(
            data.get("action_vocabulary", []))
        engine.global_action_counts = defaultdict(
            int, data.get("global_action_counts", {}))
        engine.total_global_events = data.get("total_global_events", 0)
        engine.valid_entry_actions = set(
            data.get("valid_entry_actions", []))
        engine.known_session_prefixes = set(
            data.get("known_session_prefixes", []))
        engine.timing_stats = {
            k: tuple(v) for k, v
            in data.get("timing_stats", {}).items()}
        engine.data_flow_stats = {
            k: tuple(v) for k, v
            in data.get("data_flow_stats", {}).items()}
        engine.data_flow_coverage = data.get("data_flow_coverage", {})
        engine.action_sensitivity = data.get(
            "action_sensitivity", engine.action_sensitivity)
        engine.threshold_alert = data.get(
            "threshold_alert", engine.threshold_alert)
        engine.threshold_restrict = data.get(
            "threshold_restrict", engine.threshold_restrict)
        engine.threshold_block = data.get(
            "threshold_block", engine.threshold_block)
        engine.rarity_threshold = data.get(
            "rarity_threshold", engine.rarity_threshold)
        engine.c4_thresholds = data.get("c4_thresholds", {})
        engine.c5_thresholds = data.get("c5_thresholds", {})
        return engine

    def save(self, path: str) -> None:
        """Save engine to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "SCAPEEngine":
        """Load engine from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    # ------------------------------------------------------------------
    # Legacy probability helpers (kept for backward compat)
    # ------------------------------------------------------------------
    def _get_transition_prob(self, prev_action: str,
                             curr_action: str) -> float:
        """Laplace-smoothed transition probability (delegates to score_c1)."""
        return self.score_c1(prev_action, curr_action)

    def _get_resource_prob(self, action: str, resource: str) -> float:
        """Resource probability (binary — delegates to score_c2)."""
        return self.score_c2(action, resource)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _extract_resource(self, event: Dict[str, Any]) -> str:
        params = event.get("requestParameters") or {}
        if not isinstance(params, dict):
            return "unknown"

        if "bucketName" in params:
            return f"arn:aws:s3:::{params['bucketName']}"
        if "tableName" in params:
            region = params.get("awsRegion", "us-east-1")
            return (f"arn:aws:dynamodb:{region}:"
                    f"000000000000:table/{params['tableName']}")
        if "logGroupName" in params:
            region = params.get("awsRegion", "us-east-1")
            return (f"arn:aws:logs:{region}:"
                    f"000000000000:log-group:{params['logGroupName']}")
        if "queueUrl" in params:
            return params["queueUrl"]
        if "keyId" in params:
            region = params.get("awsRegion", "us-east-1")
            return (f"arn:aws:kms:{region}:"
                    f"000000000000:key/{params['keyId']}")
        if "secretId" in params:
            return params["secretId"]
        if "functionName" in params:
            region = params.get("awsRegion", "us-east-1")
            return (f"arn:aws:lambda:{region}:"
                    f"000000000000:function:{params['functionName']}")
        if "roleName" in params:
            return f"arn:aws:iam::000000000000:role/{params['roleName']}"
        return "unknown"

    def _extract_size(self, event: Dict[str, Any]) -> Optional[float]:
        data = event.get("additionalEventData", {}) or {}
        size = data.get("bytesTransferredOut")
        if size is None:
            return None
        try:
            return float(size)
        except (TypeError, ValueError):
            return None

    def _parse_time(self, ts_str: str) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        if len(ts_str) == 7 and ts_str[4] == "-":
            ts_str += "-01"
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
