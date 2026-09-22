"""Stage 4/5: Shadow-mode and live-blocking Lambda handler wrapper.

Drop this in as an EventBridge rule handler or Lambda sidecar.
Evaluates every CloudTrail event through SCAPE and:
  - In shadow mode: logs BLOCK decisions but takes no action.
  - In live mode:   revokes credentials / alerts on BLOCK.

Controlled via environment variables:
  SCAPE_MODEL_PATH       — path/S3 key of trained engine JSON.
  SCAPE_BLOCKING_ENABLED — set to "true" to enable live blocking.
  SCAPE_SHADOW_LOG_GROUP — CloudWatch log group for shadow blocks.
"""

import json
import logging
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine
from src.session_tracker import SessionTracker
from src.tau_calibrator import TauCalibrator

# ── Feature flag — flip to "true" in Lambda env vars, no redeploy needed ────
SCAPE_BLOCKING_ENABLED = os.environ.get("SCAPE_BLOCKING_ENABLED", "false") == "true"

# ── Model path ───────────────────────────────────────────────────────────────
MODEL_PATH = os.environ.get("SCAPE_MODEL_PATH", "models/my_engine.json")

# ── Optional phi log for rolling recalibration ────────────────────────────
PHI_LOG_PATH = os.environ.get("SCAPE_PHI_LOG_PATH", "data/logs/phi_log.jsonl")

logger = logging.getLogger("scape_handler")
logging.basicConfig(level=logging.INFO)

# ── Module-level singletons (survive Lambda warm container reuse) ──────────
_engine: SCAPEEngine = None
_tracker: SessionTracker = None
_calibrator: TauCalibrator = None


def _load_engine() -> SCAPEEngine:
    global _engine, _tracker, _calibrator
    if _engine is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"No trained model at {MODEL_PATH}. "
                "Run train_my_logs.py first."
            )
        _engine = SCAPEEngine.load(MODEL_PATH)
        _tracker = SessionTracker()
        _calibrator = TauCalibrator(PHI_LOG_PATH)
        mode = "LIVE BLOCKING" if SCAPE_BLOCKING_ENABLED else "SHADOW OBSERVE"
        logger.info(f"SCAPE engine loaded. Mode: {mode}  tau={_engine.tau:.4f}")
    return _engine


def _revoke_credentials(session_id: str, event: dict):
    """Placeholder: revoke IAM temporary credentials for this session.
    
    IRL: call IAM.delete_role_policy / STS.revoke_session / flag in SIEM.
    """
    logger.critical(
        "SCAPE_BLOCK_ACTION | Revoking credentials for session %s | event=%s",
        session_id,
        json.dumps(event, default=str),
    )
    # TODO: implement boto3 credential revocation here


def evaluate_cloudtrail_event(event: dict) -> dict:
    """Evaluate a single CloudTrail event dict through SCAPE.
    
    Returns the evaluation result dict (phi, decision, violations, scores).
    """
    engine = _load_engine()
    ctx = _tracker.get_context(event)

    result = engine.evaluate_event(
        prev_action=ctx["prev_action"],
        curr_event=event,
        prev_timestamp=ctx["prev_timestamp"],
        session_age_seconds=ctx.get("session_age_seconds", 0.0),
    )

    # Log phi for rolling recalibration (Fix 4)
    _calibrator.log_phi(result["phi"], label="normal")

    if result["decision"] == "BLOCK":
        if SCAPE_BLOCKING_ENABLED:
            # Stage 5: Live blocking
            logger.warning(
                "SCAPE_BLOCK | phi=%.4f | violations=%s | session=%s",
                result["phi"],
                result["violations"],
                ctx["session_id"],
            )
            _revoke_credentials(ctx["session_id"], event)
        else:
            # Stage 4: Shadow mode — log it, don't act
            logger.warning(
                "SCAPE_SHADOW_BLOCK | phi=%.4f | violations=%s | session=%s",
                result["phi"],
                result["violations"],
                ctx["session_id"],
            )

    return result


def lambda_handler(event: dict, context) -> dict:
    """AWS Lambda entry point for EventBridge-triggered CloudTrail events."""
    records = event.get("Records", [event])
    results = []

    for record in records:
        # EventBridge wraps CloudTrail events in detail
        ct_event = record.get("detail", record)
        try:
            result = evaluate_cloudtrail_event(ct_event)
            results.append({
                "decision": result["decision"],
                "phi": round(result["phi"], 6),
                "violations": result["violations"],
            })
        except Exception as exc:
            logger.error("SCAPE evaluation error: %s", exc, exc_info=True)
            results.append({"decision": "ALLOW", "phi": 1.0, "violations": []})

    return {"statusCode": 200, "body": json.dumps(results)}
