"""Task 8: Multi-Account SCAPE Engine.

Manages per-account SCAPE engine instances with cross-account anomaly
detection. Supports:
  - Isolated per-account models (each account has its own trained baseline)
  - Cross-account correlation (detects credential movement between accounts)
  - Unified evaluation API
  - Per-account and global statistics
"""

import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure src is importable
import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine
from src.session_tracker import SessionTracker


class MultiAccountEngine:
    """Orchestrates multiple per-account SCAPE engines.

    Each AWS account gets its own trained SCAPEEngine instance.
    Cross-account checks detect lateral movement between accounts.
    """

    def __init__(self):
        self._engines: Dict[str, SCAPEEngine] = {}
        self._session_trackers: Dict[str, SessionTracker] = {}
        self._cross_account_sessions: Dict[str, List[str]] = defaultdict(list)
        # session_id -> list of account_ids seen

        # Cross-account thresholds
        self.cross_account_alert_threshold = 2  # Alert if session spans 2+ accounts
        self.cross_account_block_threshold = 4  # Block if session spans 4+ accounts

    # ------------------------------------------------------------------
    # Account Management
    # ------------------------------------------------------------------
    def add_account(self, account_id: str, engine: Optional[SCAPEEngine] = None):
        """Register an AWS account with an optional pre-trained engine."""
        if engine is None:
            engine = SCAPEEngine()
        self._engines[account_id] = engine
        self._session_trackers[account_id] = SessionTracker()

    def remove_account(self, account_id: str):
        """Remove an account and its associated engine."""
        self._engines.pop(account_id, None)
        self._session_trackers.pop(account_id, None)

    def get_engine(self, account_id: str) -> Optional[SCAPEEngine]:
        """Get the engine for a specific account."""
        return self._engines.get(account_id)

    @property
    def account_ids(self) -> List[str]:
        return sorted(self._engines.keys())

    @property
    def account_count(self) -> int:
        return len(self._engines)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train_account(self, account_id: str, logs: List[Dict]):
        """Train a specific account's engine on its normal logs."""
        if account_id not in self._engines:
            self.add_account(account_id)
        self._engines[account_id].train_from_logs(logs)

    def train_from_multi_account_logs(self, logs: List[Dict],
                                       account_field: str = "recipientAccountId"):
        """Auto-partition logs by account and train each engine.

        Args:
            logs: List of CloudTrail events with an account identifier field.
            account_field: The event field containing the AWS account ID.
        """
        partitioned: Dict[str, List[Dict]] = defaultdict(list)
        for event in logs:
            acct = event.get(account_field, "unknown")
            partitioned[acct].append(event)

        for account_id, account_logs in partitioned.items():
            self.train_account(account_id, account_logs)
            print(f"  Account {account_id}: trained on {len(account_logs)} events")

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate_event(self, event: Dict,
                       account_id: Optional[str] = None,
                       account_field: str = "recipientAccountId") -> Dict:
        """Evaluate a single event against its account's engine.

        Performs both per-account checks and cross-account correlation.

        Args:
            event: CloudTrail event dict.
            account_id: Explicit account ID. If None, extracted from event.
            account_field: Event field for account ID extraction.

        Returns:
            Result dict with 'decision', 'anomaly_score', 'violations',
            'cross_account_alert', and 'account_id'.
        """
        if account_id is None:
            account_id = event.get(account_field, "unknown")

        # Auto-register unknown accounts
        if account_id not in self._engines:
            self.add_account(account_id)

        engine = self._engines[account_id]
        tracker = self._session_trackers[account_id]

        # Get session context
        ctx = tracker.get_context(event)

        # Per-account evaluation
        result = engine.evaluate_event(
            prev_action=ctx["prev_action"],
            curr_event=event,
            prev_timestamp=ctx["prev_timestamp"],
        )

        # Cross-account correlation
        session_id = ctx["session_id"]
        cross_alert = self._check_cross_account(session_id, account_id)
        result["cross_account_alert"] = cross_alert
        result["account_id"] = account_id

        # Escalate decision if cross-account anomaly detected
        if cross_alert["is_anomalous"]:
            cross_score = cross_alert["score"]
            if cross_score > result["anomaly_score"]:
                result["anomaly_score"] = cross_score
                result["violations"].append(
                    f"CROSS: Session {session_id} spans {cross_alert['account_count']} accounts"
                )
                # Re-evaluate decision with higher score
                if cross_score >= engine.threshold_block:
                    result["decision"] = "BLOCK"
                elif cross_score >= engine.threshold_restrict:
                    result["decision"] = "TEMPORARY_RESTRICT"
                elif cross_score >= engine.threshold_alert:
                    result["decision"] = "ALLOW_WITH_ALERT"

        return result

    def evaluate_events(self, events: List[Dict],
                        account_field: str = "recipientAccountId") -> List[Dict]:
        """Evaluate a batch of events, auto-routing by account."""
        results = []
        for event in events:
            result = self.evaluate_event(event, account_field=account_field)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Cross-Account Detection
    # ------------------------------------------------------------------
    def _check_cross_account(self, session_id: str, account_id: str) -> Dict:
        """Detect if a session is traversing multiple accounts.

        Returns a dict with is_anomalous, account_count, accounts, and score.
        """
        if account_id not in self._cross_account_sessions[session_id]:
            self._cross_account_sessions[session_id].append(account_id)

        accounts = self._cross_account_sessions[session_id]
        unique_count = len(set(accounts))

        is_anomalous = unique_count >= self.cross_account_alert_threshold
        # Score scales with number of accounts touched
        if is_anomalous:
            score = 3.0 * math.log(unique_count)  # logarithmic scaling
        else:
            score = 0.0

        return {
            "is_anomalous": is_anomalous,
            "account_count": unique_count,
            "accounts": sorted(set(accounts)),
            "score": score,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, directory: str):
        """Save all account engines to a directory."""
        os.makedirs(directory, exist_ok=True)

        # Save each account engine
        for account_id, engine in self._engines.items():
            safe_name = account_id.replace(":", "_").replace("/", "_")
            engine_path = os.path.join(directory, f"{safe_name}.json")
            engine.save(engine_path)

        # Save metadata
        meta = {
            "version": "1.0",
            "accounts": self.account_ids,
            "cross_account_alert_threshold": self.cross_account_alert_threshold,
            "cross_account_block_threshold": self.cross_account_block_threshold,
        }
        with open(os.path.join(directory, "_meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, directory: str) -> "MultiAccountEngine":
        """Load all account engines from a directory."""
        mae = cls()

        meta_path = os.path.join(directory, "_meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            mae.cross_account_alert_threshold = meta.get("cross_account_alert_threshold", 2)
            mae.cross_account_block_threshold = meta.get("cross_account_block_threshold", 4)
            accounts = meta.get("accounts", [])
        else:
            accounts = []
            for fname in os.listdir(directory):
                if fname.endswith(".json") and fname != "_meta.json":
                    accounts.append(fname[:-5])

        for account_id in accounts:
            safe_name = account_id.replace(":", "_").replace("/", "_")
            engine_path = os.path.join(directory, f"{safe_name}.json")
            if os.path.exists(engine_path):
                engine = SCAPEEngine.load(engine_path)
                mae.add_account(account_id, engine)

        return mae

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """Return aggregate statistics across all accounts."""
        stats = {
            "total_accounts": self.account_count,
            "accounts": {},
            "cross_account_sessions": len(self._cross_account_sessions),
        }

        total_events = 0
        total_actions = set()

        for account_id, engine in self._engines.items():
            acct_events = engine.total_global_events
            acct_actions = len(engine.global_action_counts)
            total_events += acct_events
            total_actions.update(engine.global_action_counts.keys())

            stats["accounts"][account_id] = {
                "total_events": acct_events,
                "unique_actions": acct_actions,
                "transitions_learned": len(engine.allowed_transitions),
                "active_sessions": self._session_trackers.get(account_id,
                                                                SessionTracker()).active_sessions,
            }

        stats["total_events"] = total_events
        stats["total_unique_actions"] = len(total_actions)

        # Cross-account anomalies
        multi_acct_sessions = {
            sid: accts for sid, accts in self._cross_account_sessions.items()
            if len(set(accts)) >= self.cross_account_alert_threshold
        }
        stats["cross_account_anomalies"] = len(multi_acct_sessions)

        return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-account SCAPE engine CLI.")
    sub = parser.add_subparsers(dest="command")

    # Train
    train_p = sub.add_parser("train", help="Train from multi-account logs.")
    train_p.add_argument("log_file", help="Path to JSON log file.")
    train_p.add_argument("--account-field", default="recipientAccountId")
    train_p.add_argument("--output-dir", default="models/multi_account")

    # Evaluate
    eval_p = sub.add_parser("evaluate", help="Evaluate events.")
    eval_p.add_argument("log_file", help="Path to JSON event file.")
    eval_p.add_argument("--model-dir", default="models/multi_account")
    eval_p.add_argument("--account-field", default="recipientAccountId")

    # Stats
    stats_p = sub.add_parser("stats", help="Show statistics.")
    stats_p.add_argument("--model-dir", default="models/multi_account")

    args = parser.parse_args()

    if args.command == "train":
        with open(args.log_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        logs = data.get("Records", data) if isinstance(data, dict) else data

        mae = MultiAccountEngine()
        print(f"Training on {len(logs)} events...")
        mae.train_from_multi_account_logs(logs, account_field=args.account_field)
        mae.save(args.output_dir)
        print(f"Saved {mae.account_count} account models to {args.output_dir}")

    elif args.command == "evaluate":
        mae = MultiAccountEngine.load(args.model_dir)
        with open(args.log_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        logs = data.get("Records", data) if isinstance(data, dict) else data

        results = mae.evaluate_events(logs, account_field=args.account_field)
        decisions = defaultdict(int)
        cross_alerts = 0
        for r in results:
            decisions[r["decision"]] += 1
            if r["cross_account_alert"]["is_anomalous"]:
                cross_alerts += 1

        print(f"\n=== Multi-Account Evaluation ({mae.account_count} accounts) ===")
        print(f"Total events: {len(results)}")
        for dec in ["ALLOW", "ALLOW_WITH_ALERT", "TEMPORARY_RESTRICT", "BLOCK"]:
            cnt = decisions.get(dec, 0)
            print(f"  {dec:<22} {cnt:>6}")
        print(f"Cross-account alerts:  {cross_alerts}")

    elif args.command == "stats":
        mae = MultiAccountEngine.load(args.model_dir)
        stats = mae.get_statistics()
        print(json.dumps(stats, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
