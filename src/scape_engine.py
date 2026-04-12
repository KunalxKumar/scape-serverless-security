import json
import math
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional

class SCAPEEngine:
    """
    Structural Context-Aware Probabilistic Engine
    Implements C0-C5 checks with probabilistic scoring.
    C0: Session entry-point validation
    C1: Transition check
    C2: Resource check
    C3: Global rarity check
    C4: Timing check
    C5: Data flow check
    """

    def __init__(self):
        self.allowed_transitions: Dict[str, Set[str]] = defaultdict(set)
        self.allowed_resources: Dict[str, Set[str]] = defaultdict(set)
        self.transition_probs: Dict[Tuple[str, str], float] = {}
        self.resource_probs: Dict[Tuple[str, str], float] = {}
        self.action_sensitivity = {
            "s3:GetObject": 1.0,
            "dynamodb:PutItem": 1.0,
            "logs:PutLogEvents": 0.5,
            "s3:DeleteBucket": 10.0,
            "iam:CreateUser": 10.0,
            "s3:PutObject": 1.5,
            "dynamodb:DeleteTable": 8.0
        }
        # Timing stats: action -> (mean, std)
        self.timing_stats: Dict[str, Tuple[float, float]] = {}
        # Global action counts (simulated cross-function)
        self.global_action_counts: Dict[str, int] = defaultdict(int)
        self.total_global_events = 0
        # C0: Session entry-point validation
        self.valid_entry_actions: Set[str] = set()  # Actions that can start a session
        self.known_session_prefixes: Set[str] = set()  # Known session ID patterns
        self.seen_sessions: Set[str] = set()  # Sessions seen during training

    def train_from_logs(self, logs: List[Dict]):
        """Learn normal behavior from trusted CloudTrail logs."""
        transition_counts = defaultdict(int)
        resource_counts = defaultdict(lambda: defaultdict(int))
        timing_values = defaultdict(list)
        session_prev_action = {}  # session_id -> last action

        start_time = None
        if logs:
            start_time = self._parse_time(logs[0].get('eventTime', ''))

        for event in logs:
            action = event['eventName']
            resource = self._extract_resource(event)
            session_id = event.get('sessionId', 'default')
            timestamp = self._parse_time(event.get('eventTime', ''))
            size = event.get('additionalEventData', {}).get('bytesTransferredOut', 0)

            # C3: Global rarity tracking
            self.global_action_counts[action] += 1
            self.total_global_events += 1

            # C4: Timing tracking
            if start_time:
                rel_time = (timestamp - start_time).total_seconds()
                timing_values[action].append(rel_time)

            # Resource tracking
            if resource and resource != "unknown":
                resource_counts[action][resource] += 1

            # C0: Track session entry points
            if session_id not in session_prev_action:
                # First event in this session => it's a valid entry action
                self.valid_entry_actions.add(action)
                self.seen_sessions.add(session_id)
                # Extract session prefix (e.g., "session" from "session-0")
                prefix = session_id.rsplit('-', 1)[0] if '-' in session_id else session_id
                self.known_session_prefixes.add(prefix)

            # Transition tracking (C1)
            if session_id in session_prev_action:
                prev_action = session_prev_action[session_id]
                transition_counts[(prev_action, action)] += 1

            session_prev_action[session_id] = action

        # Build allowed transitions
        for (a, b), count in transition_counts.items():
            self.allowed_transitions[a].add(b)

        # Build allowed resources
        for action, res_dict in resource_counts.items():
            for res in res_dict.keys():
                self.allowed_resources[action].add(res)

        # Compute probabilities (for surprise calculation)
        total_transitions = sum(transition_counts.values()) or 1
        for pair, count in transition_counts.items():
            self.transition_probs[pair] = count / total_transitions

        for action, res_dict in resource_counts.items():
            total_res = sum(res_dict.values())
            for res, count in res_dict.items():
                self.resource_probs[(action, res)] = count / total_res

        # Compute timing stats
        for action, times in timing_values.items():
            if times:
                mean = sum(times) / len(times)
                variance = sum((t - mean) ** 2 for t in times) / len(times)
                std = math.sqrt(variance) if variance > 0 else 1.0
                self.timing_stats[action] = (mean, std)

    def evaluate_event(self, prev_action: Optional[str], curr_event: Dict) -> Dict:
        """Evaluate a single event and return decision with details."""
        curr_action = curr_event['eventName']
        resource = self._extract_resource(curr_event)
        session_id = curr_event.get('sessionId', 'default')
        timestamp = self._parse_time(curr_event.get('eventTime', ''))
        size = curr_event.get('additionalEventData', {}).get('bytesTransferredOut', 0)

        violations = []
        surprise_scores = []
        weights = []

        # C0: Session Entry-Point Validation
        w0 = 0.20
        c0_surprise = 0.0
        if prev_action is None:
            # This is the first event in a session — validate entry point
            # Check if session ID pattern is known
            prefix = session_id.rsplit('-', 1)[0] if '-' in session_id else session_id
            unknown_session = prefix not in self.known_session_prefixes
            unknown_entry = curr_action not in self.valid_entry_actions

            if unknown_session:
                violations.append(f"C0: Unknown session prefix '{prefix}'")
                c0_surprise = 13.8  # -log(1e-6), maximum surprise
            elif unknown_entry:
                violations.append(f"C0: '{curr_action}' is not a valid session entry action")
                c0_surprise = 10.0
        surprise_scores.append(c0_surprise)
        weights.append(w0)

        # C1: Transition Check
        w1 = 0.20
        if prev_action and curr_action not in self.allowed_transitions.get(prev_action, set()):
            violations.append(f"C1: {prev_action} -> {curr_action}")
            prob = self.transition_probs.get((prev_action, curr_action), 1e-6)
            surprise = -math.log(prob)
            surprise_scores.append(surprise)
            weights.append(w1)
        else:
            surprise_scores.append(0.0)
            weights.append(w1)

        # C2: Resource Check
        w2 = 0.30
        if curr_action in self.allowed_resources and resource != "unknown":
            if resource not in self.allowed_resources[curr_action]:
                violations.append(f"C2: Resource {resource} for {curr_action}")
                prob = self.resource_probs.get((curr_action, resource), 1e-6)
                surprise = -math.log(prob)
                surprise_scores.append(surprise)
                weights.append(w2)
        else:
            surprise_scores.append(0.0)
            weights.append(w2)

        # C3: Global Rarity Check
        w3 = 0.15
        global_freq = self.global_action_counts[curr_action] / max(self.total_global_events, 1)
        rarity_threshold = 0.01  # 1%
        if global_freq < rarity_threshold:
            violations.append(f"C3: Rare action {curr_action} (freq={global_freq:.4f})")
            surprise = -math.log(global_freq + 1e-6)
            surprise_scores.append(surprise)
            weights.append(w3)
        else:
            surprise_scores.append(0.0)
            weights.append(w3)

        # C4: Timing Check
        w4 = 0.10
        if curr_action in self.timing_stats:
            mean, std = self.timing_stats[curr_action]
            if std > 0:
                # For this event, we'd need its relative time from session start.
                # Simplified: we don't have session start tracking here, so skip.
                pass
        surprise_scores.append(0.0)
        weights.append(w4)

        # C5: Data Flow (placeholder)
        w5 = 0.20
        surprise_scores.append(0.0)
        weights.append(w5)

        # Compute weighted anomaly score
        total_score = sum(s * w for s, w in zip(surprise_scores, weights))
        sensitivity = self.action_sensitivity.get(curr_action, 2.0)
        total_score *= sensitivity

        # Decision
        if total_score < 1.0:
            decision = "ALLOW"
        elif total_score < 2.5:
            decision = "ALLOW_WITH_ALERT"
        elif total_score < 5.0:
            decision = "TEMPORARY_RESTRICT"
        else:
            decision = "BLOCK"

        return {
            "decision": decision,
            "anomaly_score": total_score,
            "violations": violations,
            "surprise_breakdown": dict(zip(["C0","C1","C2","C3","C4","C5"], surprise_scores))
        }

    def _evaluate_event_internal(self, prev_action: Optional[str], curr_event: Dict, disabled_checks: Set[str]) -> Dict:
        """Internal evaluation with ability to disable specific checks."""
        curr_action = curr_event['eventName']
        resource = self._extract_resource(curr_event)
        session_id = curr_event.get('sessionId', 'default')
        timestamp = self._parse_time(curr_event.get('eventTime', ''))
        
        violations = []
        scores = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]  # C0 to C5
        weights = [0.20, 0.20, 0.30, 0.15, 0.10, 0.20]
        
        # C0: Session Entry-Point Validation
        if 'C0' not in disabled_checks and prev_action is None:
            prefix = session_id.rsplit('-', 1)[0] if '-' in session_id else session_id
            unknown_session = prefix not in self.known_session_prefixes
            unknown_entry = curr_action not in self.valid_entry_actions

            if unknown_session:
                violations.append(f"C0: Unknown session prefix '{prefix}'")
                scores[0] = 13.8 
            elif unknown_entry:
                violations.append(f"C0: '{curr_action}' is not valid entry")
                scores[0] = 10.0

        # C1: Transition Check
        if 'C1' not in disabled_checks and prev_action:
            if curr_action not in self.allowed_transitions.get(prev_action, set()):
                violations.append(f"C1: {prev_action} -> {curr_action}")
                prob = self.transition_probs.get((prev_action, curr_action), 1e-6)
                scores[1] = -math.log(prob)

        # C2: Resource Check
        if 'C2' not in disabled_checks and resource != "unknown":
            if curr_action in self.allowed_resources and resource not in self.allowed_resources[curr_action]:
                violations.append(f"C2: Resource {resource}")
                prob = self.resource_probs.get((curr_action, resource), 1e-6)
                scores[2] = -math.log(prob)

        # C3: Global Rarity Check
        if 'C3' not in disabled_checks:
            global_freq = self.global_action_counts[curr_action] / max(self.total_global_events, 1)
            if global_freq < 0.01:
                violations.append(f"C3: Rare action {curr_action}")
                scores[3] = -math.log(global_freq + 1e-6)

        # C4 and C5 (Placeholders)
        
        # Compute weighted anomaly score
        total_score = sum(s * w for s, w in zip(scores, weights))
        sensitivity = self.action_sensitivity.get(curr_action, 2.0)
        total_score *= sensitivity

        # Decision
        if total_score < 1.0:
            decision = "ALLOW"
        elif total_score < 2.5:
            decision = "ALLOW_WITH_ALERT"
        elif total_score < 5.0:
            decision = "TEMPORARY_RESTRICT"
        else:
            decision = "BLOCK"

        return {
            "decision": decision,
            "anomaly_score": total_score,
            "violations": violations,
            "surprise_breakdown": dict(zip(["C0","C1","C2","C3","C4","C5"], scores))
        }

    def _extract_resource(self, event: Dict) -> str:
        params = event.get('requestParameters')
        if not params:
            return "unknown"
        if 'bucketName' in params:
            return f"s3://{params['bucketName']}"
        elif 'tableName' in params:
            return f"dynamodb://{params['tableName']}"
        elif 'logGroupName' in params:
            return f"logs://{params['logGroupName']}"
        return "unknown"


    def _parse_time(self, ts_str: str):
        from datetime import datetime, timezone
        if not ts_str:
            return datetime.now(timezone.utc)
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))

