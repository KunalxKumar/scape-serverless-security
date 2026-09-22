"""Phase 3: Robust Session Stitching for SCAPE.

Improvements over basic session tracking:
  - 3.1: Prioritizes sourceIdentity from CloudTrail sessionContext
  - 3.2: Fallback chain: sourceIdentity -> arn -> accessKeyId -> sessionId
  - 3.3: Exponential decay instead of hard timeout
  - 3.4: LRU cache for memory-efficient Lambda deployments
"""

import math
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class SessionTracker:
    """Production-grade session tracker with decay-based expiry and LRU caching.

    Groups CloudTrail events by logical session using a priority-based
    identity resolution chain. Uses exponential decay instead of hard
    timeouts to gracefully handle long-running sessions.
    """

    # Decay half-life: 15 minutes (common Lambda execution window)
    DECAY_HALF_LIFE = 900.0

    # Hard expiry: sessions inactive longer than this are fully dropped
    HARD_EXPIRY = 7200.0  # 2 hours

    # Maximum sessions to track (LRU eviction for Lambda memory efficiency)
    MAX_SESSIONS = 10000

    def __init__(self, max_sessions: int = 10000, decay_half_life: float = 900.0):
        self.MAX_SESSIONS = max_sessions
        self.DECAY_HALF_LIFE = decay_half_life
        # OrderedDict for LRU behavior
        self._sessions: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_context(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Return session context for *event* and update session state.

        Returns a dict with:
            prev_action:      last action in this session (or None)
            prev_timestamp:   datetime of last action (or None)
            history:          list of previous action names in this session
            session_id:       resolved session identifier
            transition_decay: float 0-1, how much to trust the transition
                              (1.0 = just happened, 0.0 = ancient)
        """
        session_id = self._resolve_session_id(event)
        timestamp = self._parse_time(event.get("eventTime", ""))
        action = event.get("eventName", "Unknown")

        ctx = self._sessions.get(session_id)

        # Compute decay factor
        transition_decay = 1.0
        if ctx and ctx.get("prev_timestamp"):
            gap = (timestamp - ctx["prev_timestamp"]).total_seconds()

            # Hard expiry
            if gap > self.HARD_EXPIRY:
                ctx = None
                transition_decay = 0.0
            else:
                # Exponential decay: e^(-gap / half_life)
                transition_decay = math.exp(-abs(gap) / self.DECAY_HALF_LIFE)

        if ctx is None:
            ctx = {
                "prev_action": None,
                "prev_timestamp": None,
                "first_seen": timestamp,
                "history": [],
            }
            transition_decay = 0.0  # no previous action

        age_seconds = (timestamp - ctx["first_seen"]).total_seconds() if ctx["first_seen"] else 0.0

        result = {
            "prev_action": ctx["prev_action"],
            "prev_timestamp": ctx["prev_timestamp"],
            "session_age_seconds": max(0.0, age_seconds),
            "history": list(ctx["history"][-50:]),  # cap history length
            "session_id": session_id,
            "transition_decay": transition_decay,
        }

        # Update session state
        ctx["prev_action"] = action
        ctx["prev_timestamp"] = timestamp
        ctx["history"].append(action)

        # Trim history to prevent memory bloat
        if len(ctx["history"]) > 100:
            ctx["history"] = ctx["history"][-50:]

        # LRU: move to end and enforce max size
        self._sessions[session_id] = ctx
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > self.MAX_SESSIONS:
            self._sessions.popitem(last=False)

        return result

    def reset(self):
        """Clear all tracked sessions."""
        self._sessions.clear()

    @property
    def active_sessions(self) -> int:
        return len(self._sessions)

    def get_session_stats(self) -> Dict[str, Any]:
        """Return summary statistics about tracked sessions."""
        if not self._sessions:
            return {"active": 0, "avg_history_len": 0}
        histories = [len(s.get("history", [])) for s in self._sessions.values()]
        return {
            "active": len(self._sessions),
            "avg_history_len": sum(histories) / len(histories),
            "max_history_len": max(histories),
        }

    # ------------------------------------------------------------------
    # Identity Resolution (Phase 3.1 + 3.2)
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_session_id(event: Dict[str, Any]) -> str:
        """Extract the best session identifier from a CloudTrail event.

        Priority chain:
        1. sourceIdentity (most stable, survives credential rotations)
        2. ARN + sourceIPAddress (pseudo-stable across temp creds)
        3. ARN alone
        4. accessKeyId
        5. userName or principalId
        6. Explicit sessionId (from SCAPE-formatted events)
        7. Fallback to 'default'
        """
        uid = event.get("userIdentity", {})
        src_ip = event.get("sourceIPAddress", "")

        if isinstance(uid, dict):
            # Priority 1: sourceIdentity (most stable)
            session_ctx = uid.get("sessionContext", {})
            if isinstance(session_ctx, dict):
                issuer = session_ctx.get("sessionIssuer", {})
                if isinstance(issuer, dict) and issuer.get("sourceIdentity"):
                    return issuer["sourceIdentity"]
                attrs = session_ctx.get("attributes", {})
                if isinstance(attrs, dict) and attrs.get("sourceIdentity"):
                    return attrs["sourceIdentity"]

            # Priority 2: ARN + sourceIP (pseudo-stable)
            arn = uid.get("arn")
            if arn and src_ip:
                return f"{arn}:{src_ip}"

            # Priority 3: ARN alone
            if arn:
                return arn

            # Priority 4: accessKeyId
            if uid.get("accessKeyId"):
                return uid["accessKeyId"]

            # Priority 5: userName or principalId
            if uid.get("userName"):
                return uid["userName"]
            if uid.get("principalId"):
                return uid["principalId"]

        # Priority 6: explicit sessionId
        if event.get("sessionId"):
            return event["sessionId"]

        return "default"

    @staticmethod
    def _parse_time(ts_str: str) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
