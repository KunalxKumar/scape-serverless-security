"""Phase 4: Guarded Online Learning with Shadow Model.

Supports:
  4.1: Whitelist table for human-confirmed benign events
  4.2: Shadow model that learns in parallel, promoted on review
  4.3: Anomaly-aware learning (only learns from ALLOW events)
"""

import json
import math
import os
import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine
from src.session_tracker import SessionTracker


class GuardedLearningEngine:
    """Wraps a live + shadow SCAPEEngine pair for safe online learning.

    The live model is used for scoring. The shadow model is updated
    incrementally with ALLOW events. Periodically, a human reviews
    the shadow model's statistics and promotes it to live.
    """

    def __init__(self, live_engine: Optional[SCAPEEngine] = None):
        self.live = live_engine or SCAPEEngine()
        self.shadow = copy.deepcopy(self.live)
        self.tracker = SessionTracker()

        # Whitelist: set of (action, resource) tuples confirmed benign
        self.whitelist: Set[tuple] = set()

        # Statistics for shadow review
        self.shadow_events_learned = 0
        self.shadow_new_actions: Set[str] = set()
        self.shadow_new_transitions: Set[tuple] = set()

        # Alert log for human review
        self.alert_log: List[Dict] = []
        self.max_alert_log = 1000

    # ------------------------------------------------------------------
    # Core: Evaluate + Learn
    # ------------------------------------------------------------------
    def evaluate(self, event: Dict[str, Any]) -> Dict:
        """Score event with live model, update shadow model if safe.

        Phase 4.3: Only the shadow model learns, and only from events
        the live model scored as ALLOW.
        """
        ctx = self.tracker.get_context(event)
        action = event.get("eventName", "Unknown")
        resource = self._extract_resource_key(event)

        # Check whitelist first
        if (action, resource) in self.whitelist:
            return {
                "decision": "ALLOW",
                "phi": 1.0,
                "scores": {},
                "violations": [],
                "whitelisted": True,
                # Backward compat
                "anomaly_score": 1.0,
                "surprise_breakdown": {},
            }

        # Score with live model
        result = self.live.evaluate_event(
            prev_action=ctx["prev_action"],
            curr_event=event,
            prev_timestamp=ctx["prev_timestamp"],
        )
        result["whitelisted"] = False

        # Log alerts
        if result["decision"] != "ALLOW":
            self._log_alert(event, result)

        # Phase 4.3: Shadow learns only from safe events
        if result["decision"] == "ALLOW":
            session_state = {
                "prev_action": ctx["prev_action"],
                "prev_timestamp": ctx["prev_timestamp"],
            }
            # Track new things the shadow is learning
            if action not in self.shadow.global_action_counts:
                self.shadow_new_actions.add(action)
            if ctx["prev_action"]:
                pair = (ctx["prev_action"], action)
                if pair not in self.shadow.transition_counts:
                    self.shadow_new_transitions.add(pair)

            self.shadow.incremental_update(event, session_state)
            self.shadow_events_learned += 1

        return result

    # ------------------------------------------------------------------
    # Phase 4.1: Whitelist Management
    # ------------------------------------------------------------------
    def add_to_whitelist(self, action: str, resource: str = "*"):
        """Mark a specific (action, resource) pair as confirmed benign."""
        self.whitelist.add((action, resource))

    def remove_from_whitelist(self, action: str, resource: str = "*"):
        """Remove a pair from the whitelist."""
        self.whitelist.discard((action, resource))

    def get_whitelist(self) -> List[Dict]:
        """Return current whitelist entries."""
        return [{"action": a, "resource": r} for a, r in sorted(self.whitelist)]

    # ------------------------------------------------------------------
    # Phase 4.2: Shadow Model Promotion
    # ------------------------------------------------------------------
    def get_shadow_review(self) -> Dict:
        """Return information for human review of shadow model changes."""
        return {
            "events_learned": self.shadow_events_learned,
            "new_actions": sorted(self.shadow_new_actions),
            "new_actions_count": len(self.shadow_new_actions),
            "new_transitions": [f"{a}->{b}" for a, b in sorted(self.shadow_new_transitions)],
            "new_transitions_count": len(self.shadow_new_transitions),
            "shadow_total_events": self.shadow.total_global_events,
            "shadow_unique_actions": len(self.shadow.global_action_counts),
            "live_total_events": self.live.total_global_events,
            "live_unique_actions": len(self.live.global_action_counts),
            "recent_alerts": len(self.alert_log),
        }

    def promote_shadow(self):
        """Promote the shadow model to live (after human review).

        Resets the shadow to a copy of the newly promoted live model.
        """
        self.live = self.shadow
        self.shadow = copy.deepcopy(self.live)
        self.shadow_events_learned = 0
        self.shadow_new_actions.clear()
        self.shadow_new_transitions.clear()
        self.alert_log.clear()

    def reject_shadow(self):
        """Discard shadow model changes and reset to live copy."""
        self.shadow = copy.deepcopy(self.live)
        self.shadow_events_learned = 0
        self.shadow_new_actions.clear()
        self.shadow_new_transitions.clear()

    # ------------------------------------------------------------------
    # Alert Log
    # ------------------------------------------------------------------
    def _log_alert(self, event: Dict, result: Dict):
        """Store recent alerts for review."""
        entry = {
            "timestamp": event.get("eventTime", ""),
            "action": event.get("eventName", "Unknown"),
            "session_id": event.get("sessionId", ""),
            "decision": result["decision"],
            "phi": result["phi"],
            "violations": result["violations"][:3],
        }
        self.alert_log.append(entry)
        if len(self.alert_log) > self.max_alert_log:
            self.alert_log = self.alert_log[-self.max_alert_log:]

    def get_recent_alerts(self, n: int = 20) -> List[Dict]:
        return self.alert_log[-n:]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, directory: str):
        """Save both models and whitelist."""
        os.makedirs(directory, exist_ok=True)
        self.live.save(os.path.join(directory, "live_engine.json"))
        self.shadow.save(os.path.join(directory, "shadow_engine.json"))
        meta = {
            "whitelist": [{"action": a, "resource": r} for a, r in self.whitelist],
            "shadow_events_learned": self.shadow_events_learned,
            "shadow_new_actions": sorted(self.shadow_new_actions),
            "shadow_new_transitions": [list(t) for t in self.shadow_new_transitions],
        }
        with open(os.path.join(directory, "guarded_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, directory: str) -> "GuardedLearningEngine":
        """Load both models and whitelist."""
        live_path = os.path.join(directory, "live_engine.json")
        shadow_path = os.path.join(directory, "shadow_engine.json")
        meta_path = os.path.join(directory, "guarded_meta.json")

        live = SCAPEEngine.load(live_path) if os.path.exists(live_path) else SCAPEEngine()
        gle = cls(live_engine=live)

        if os.path.exists(shadow_path):
            gle.shadow = SCAPEEngine.load(shadow_path)
        else:
            gle.shadow = copy.deepcopy(live)

        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
            gle.whitelist = {(e["action"], e["resource"]) for e in meta.get("whitelist", [])}
            gle.shadow_events_learned = meta.get("shadow_events_learned", 0)
            gle.shadow_new_actions = set(meta.get("shadow_new_actions", []))
            gle.shadow_new_transitions = {tuple(t) for t in meta.get("shadow_new_transitions", [])}

        return gle

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_resource_key(event: Dict) -> str:
        params = event.get("requestParameters") or {}
        if not isinstance(params, dict):
            return "*"
        for key in ("bucketName", "tableName", "functionName", "logGroupName"):
            if key in params:
                return str(params[key])
        return "*"
