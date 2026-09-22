"""Production SCAPE Lambda Detector with end-to-end integration.

Reads trained JSON model from S3 (cached in /tmp).
Consults DynamoDB whitelist before scoring.
Updates shadow model with ALLOW events (guarded online learning).
Emits CloudWatch custom metrics.
Sends SNS alerts with "Mark as Benign" context.
Batches DynamoDB session state writes.

Environment variables:
  MODEL_BUCKET         - S3 bucket for model JSON
  MODEL_KEY            - S3 key for model JSON
  STATE_TABLE          - DynamoDB table for session state
  WHITELIST_TABLE      - DynamoDB table for whitelisted actions
  SHADOW_BUCKET        - S3 bucket for shadow model (optional)
  SHADOW_KEY           - S3 key for shadow model (optional)
  ALERT_TOPIC_ARN      - SNS topic for alerts
  ENFORCEMENT_MODE     - 'passive' or 'active'
  FLUSH_BATCH_SIZE     - Events before DynamoDB flush (default: 100)
  FLUSH_INTERVAL       - Seconds between DynamoDB flushes (default: 10)
  NOISE_FILTER_ACTIONS - Comma-separated actions to skip (e.g. "AssumeRole,GetCallerIdentity")
"""

import hashlib
import json
import os
import time
import copy
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("scape-detector")
logger.setLevel(logging.INFO)

# Lazy AWS imports
boto3 = None
_s3_client = None
_dynamodb = None
_sns_client = None
_cloudwatch = None


def _init_aws():
    global boto3, _s3_client, _dynamodb, _sns_client, _cloudwatch
    if boto3 is None:
        import boto3 as _boto3
        boto3 = _boto3
        _s3_client = boto3.client("s3")
        _dynamodb = boto3.resource("dynamodb")
        _sns_client = boto3.client("sns")
        _cloudwatch = boto3.client("cloudwatch")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MODEL_BUCKET = os.environ.get("MODEL_BUCKET", "")
MODEL_KEY = os.environ.get("MODEL_KEY", "scape-model/my_engine.json")
STATE_TABLE = os.environ.get("STATE_TABLE", "scape-state")
WHITELIST_TABLE = os.environ.get("WHITELIST_TABLE", "")
SHADOW_BUCKET = os.environ.get("SHADOW_BUCKET", "")
SHADOW_KEY = os.environ.get("SHADOW_KEY", "scape-model/shadow_engine.json")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
ENFORCEMENT_MODE = os.environ.get("ENFORCEMENT_MODE", "passive")
FLUSH_INTERVAL = int(os.environ.get("FLUSH_INTERVAL", "10"))
FLUSH_BATCH_SIZE = int(os.environ.get("FLUSH_BATCH_SIZE", "100"))

# Noise filter: skip these actions entirely (reduces DynamoDB costs)
_NOISE_FILTER_RAW = os.environ.get("NOISE_FILTER_ACTIONS", "")
NOISE_FILTER_ACTIONS: Set[str] = set()
if _NOISE_FILTER_RAW:
    NOISE_FILTER_ACTIONS = {a.strip() for a in _NOISE_FILTER_RAW.split(",") if a.strip()}

# [FIX 6] Prefix-based noise filter — empty by default.
# The previous default ("Describe,List,Get,...") hid reconnaissance actions
# like GetCallerIdentity and GetSessionToken that are critical for detecting
# escalation paths (AssumeRole -> GetCallerIdentity -> CreateUser).
# Operators who want prefix filtering must explicitly set the env var.
_NOISE_PREFIXES_RAW = os.environ.get("NOISE_FILTER_PREFIXES", "")
NOISE_FILTER_PREFIXES = tuple(p.strip() for p in _NOISE_PREFIXES_RAW.split(",") if p.strip())

# Learning mode: log scores but always return ALLOW (Item 8)
LEARNING_MODE = os.environ.get("LEARNING_MODE", "false").lower() == "true"

# Caches
_cached_engine = None
_cached_shadow = None
_model_cache_path = "/tmp/scape_model.json"
_shadow_cache_path = "/tmp/scape_shadow.json"
_whitelist_cache: Optional[Set[str]] = None
_whitelist_cache_time: float = 0.0
WHITELIST_CACHE_TTL = 300  # 5 min

# [FIX 9] Model cache with TTL for freshness
_model_cache_time: float = 0.0
MODEL_CACHE_TTL = 300  # refresh model from S3 every 5 minutes

# [FIX 1] Session write buffer — these are reset per-invocation in
# lambda_handler() to prevent cross-invocation contamination.
_write_buffer: List[Dict] = []
_last_flush_time: float = 0.0


# ---------------------------------------------------------------------------
# Model Loading
# ---------------------------------------------------------------------------
def _load_engine():
    """Load the primary SCAPE model, with TTL-based cache invalidation."""
    global _cached_engine, _model_cache_time

    # [FIX 9] Check cache freshness — re-download from S3 if stale.
    now = time.time()
    if _cached_engine is not None and (now - _model_cache_time) < MODEL_CACHE_TTL:
        return _cached_engine

    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scape_engine import SCAPEEngine

    # If cache is stale but we have an S3 source, re-download
    if MODEL_BUCKET:
        _init_aws()
        logger.info(f"Downloading model from s3://{MODEL_BUCKET}/{MODEL_KEY}")
        _s3_client.download_file(MODEL_BUCKET, MODEL_KEY, _model_cache_path)
        _cached_engine = SCAPEEngine.load(_model_cache_path)
        _model_cache_time = time.time()
        return _cached_engine

    # Fallback: local /tmp cache or project models/ dir
    if os.path.exists(_model_cache_path):
        _cached_engine = SCAPEEngine.load(_model_cache_path)
        _model_cache_time = time.time()
        return _cached_engine

    local_path = os.path.join(os.path.dirname(__file__), "..", "models", "my_engine.json")
    if os.path.exists(local_path):
        _cached_engine = SCAPEEngine.load(local_path)
        _model_cache_time = time.time()
        return _cached_engine

    raise RuntimeError("No model found")


def _load_shadow():
    """Load the shadow model for online learning."""
    global _cached_shadow
    if _cached_shadow is not None:
        return _cached_shadow

    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scape_engine import SCAPEEngine

    if os.path.exists(_shadow_cache_path):
        _cached_shadow = SCAPEEngine.load(_shadow_cache_path)
        return _cached_shadow

    if SHADOW_BUCKET:
        _init_aws()
        try:
            _s3_client.download_file(SHADOW_BUCKET, SHADOW_KEY, _shadow_cache_path)
            _cached_shadow = SCAPEEngine.load(_shadow_cache_path)
            return _cached_shadow
        except Exception:
            pass

    # Initialize shadow from live model
    _cached_shadow = copy.deepcopy(_load_engine())
    return _cached_shadow


# ---------------------------------------------------------------------------
# Whitelist (Phase 4.1: integrated into scoring loop)
# ---------------------------------------------------------------------------
def _load_whitelist() -> Set[str]:
    """Load whitelist from DynamoDB with caching.

    [FIX 4] Uses pagination to handle whitelists > 1 MB (the single-scan
    limit). Without this, large whitelists are silently truncated.
    """
    global _whitelist_cache, _whitelist_cache_time

    now = time.time()
    if _whitelist_cache is not None and (now - _whitelist_cache_time) < WHITELIST_CACHE_TTL:
        return _whitelist_cache

    if not WHITELIST_TABLE or not boto3:
        _whitelist_cache = set()
        _whitelist_cache_time = now
        return _whitelist_cache

    try:
        table = _dynamodb.Table(WHITELIST_TABLE)
        items = []
        resp = table.scan(ProjectionExpression="action_resource")
        items.extend(resp.get("Items", []))
        # [FIX 4] Paginate through all results
        while "LastEvaluatedKey" in resp:
            resp = table.scan(
                ProjectionExpression="action_resource",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
        _whitelist_cache = {item["action_resource"] for item in items}
        _whitelist_cache_time = now
        logger.info(f"Loaded {len(_whitelist_cache)} whitelist entries")
    except Exception as e:
        logger.warning(f"Failed to load whitelist: {e}")
        _whitelist_cache = _whitelist_cache or set()
        _whitelist_cache_time = now

    return _whitelist_cache


def _is_whitelisted(action: str, resource: str = "*") -> bool:
    """Check if an (action, resource) pair is in the whitelist."""
    wl = _load_whitelist()
    # Check exact match and wildcard
    return f"{action}|{resource}" in wl or f"{action}|*" in wl


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
def _get_session_state(session_id: str) -> Optional[Dict]:
    if not STATE_TABLE or not boto3:
        return None
    try:
        table = _dynamodb.Table(STATE_TABLE)
        resp = table.get_item(Key={"session_id": session_id})
        return resp.get("Item")
    except Exception as e:
        logger.warning(f"Session state read failed: {e}")
        return None


def _buffer_session_update(session_id, action, timestamp_str, score, count=1):
    global _write_buffer, _last_flush_time
    _write_buffer.append({
        "session_id": session_id,
        "action": action,
        "timestamp": timestamp_str,
        "score": str(score),
        "count": count,
        "ttl": int(time.time()) + 3600,
    })
    now = time.time()
    if len(_write_buffer) >= FLUSH_BATCH_SIZE or (now - _last_flush_time) > FLUSH_INTERVAL:
        _flush_writes()


def _flush_writes():
    global _write_buffer, _last_flush_time
    if not _write_buffer or not STATE_TABLE or not boto3:
        _write_buffer = []
        _last_flush_time = time.time()
        return
    try:
        table = _dynamodb.Table(STATE_TABLE)
        with table.batch_writer() as batch:
            for item in _write_buffer:
                batch.put_item(Item=item)
        logger.info(f"Flushed {len(_write_buffer)} session updates")
    except Exception as e:
        logger.error(f"Flush failed: {e}")
    finally:
        _write_buffer = []
        _last_flush_time = time.time()


# ---------------------------------------------------------------------------
# Shadow Model Update (Phase 4.2+4.3: integrated into scoring)
# ---------------------------------------------------------------------------
def _update_shadow(event: Dict, session_state: Optional[Dict]):
    """Incrementally update the shadow model with a safe event."""
    shadow = _load_shadow()
    shadow.incremental_update(event, session_state)


def _save_shadow_periodically():
    """Checkpoint shadow model back to S3 every N events."""
    global _cached_shadow
    if not _cached_shadow or not SHADOW_BUCKET:
        return
    try:
        _cached_shadow.save(_shadow_cache_path)
        _s3_client.upload_file(_shadow_cache_path, SHADOW_BUCKET, SHADOW_KEY)
        logger.info("Shadow model checkpointed to S3")
    except Exception as e:
        logger.warning(f"Shadow checkpoint failed: {e}")


# ---------------------------------------------------------------------------
# Metrics + Alerts
# ---------------------------------------------------------------------------
def _emit_metrics(decision, score, action):
    if not _cloudwatch:
        return
    try:
        _cloudwatch.put_metric_data(
            Namespace="SCAPE",
            MetricData=[
                {"MetricName": "AnomalyScore", "Value": score, "Unit": "None",
                 "Dimensions": [{"Name": "Action", "Value": action}]},
                {"MetricName": "Decision", "Value": 1.0, "Unit": "Count",
                 "Dimensions": [{"Name": "DecisionType", "Value": decision}]},
            ],
        )
    except Exception:
        pass


def _send_alert(ct_event, result, session_id):
    if not ALERT_TOPIC_ARN or not _sns_client:
        return
    action = ct_event.get("eventName", "Unknown")
    resource = "*"
    params = ct_event.get("requestParameters") or {}
    if isinstance(params, dict):
        for k in ("bucketName", "tableName", "functionName"):
            if k in params:
                resource = str(params[k])
                break

    message = {
        "source": "SCAPE Detector",
        "decision": result["decision"],
        "phi": result["phi"],
        "action": action,
        "resource": resource,
        "violations": result["violations"],
        "event_time": ct_event.get("eventTime", ""),
        "session_id": session_id,
        "enforcement_mode": ENFORCEMENT_MODE,
        "mark_benign_hint": f"To whitelist: POST /whitelist with "
                            f'{{"action": "{action}", "resource": "{resource}"}}',
    }
    # [FIX 8] Log warning on SNS failure — a missed alert on a BLOCK is a
    # security gap, so we must not silently swallow the exception.
    try:
        _sns_client.publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject=f"SCAPE {result['decision']}: {action}",
            Message=json.dumps(message, indent=2, default=str),
        )
    except Exception as e:
        logger.warning(f"SNS alert failed for {action} ({result['decision']}): {e}")


# ---------------------------------------------------------------------------
# Resolve session ID (mirrors session_tracker.py logic)
# ---------------------------------------------------------------------------
def _resolve_session_id(event: Dict) -> str:
    """Extract the best session identifier from a CloudTrail event.

    [FIX 7] Falls back to a hash of the userIdentity blob instead of the
    string "default". The old behaviour caused all unresolved sessions to
    share a single DynamoDB key, corrupting C1 transition tracking.
    """
    uid = event.get("userIdentity", {})
    if isinstance(uid, dict):
        sc = uid.get("sessionContext", {})
        if isinstance(sc, dict):
            issuer = sc.get("sessionIssuer", {})
            if isinstance(issuer, dict) and issuer.get("sourceIdentity"):
                return issuer["sourceIdentity"]
            attrs = sc.get("attributes", {})
            if isinstance(attrs, dict) and attrs.get("sourceIdentity"):
                return attrs["sourceIdentity"]
        if uid.get("arn"):
            return uid["arn"]
        if uid.get("accessKeyId"):
            return uid["accessKeyId"]
        if uid.get("userName"):
            return uid["userName"]
        if uid.get("principalId"):
            return uid["principalId"]
    if event.get("sessionId"):
        return event["sessionId"]

    # [FIX 7] Deterministic fallback from identity blob instead of "default"
    fallback = hashlib.sha256(
        json.dumps(event.get("userIdentity", {}), sort_keys=True).encode()
    ).hexdigest()[:16]
    return f"unknown-{fallback}"


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------
_shadow_update_counter = 0

def lambda_handler(event: Dict, context: Any) -> Dict:
    global _shadow_update_counter, _write_buffer, _last_flush_time

    # [FIX 1] Reset write buffer per-invocation to prevent cross-invocation
    # contamination in warm Lambda containers. A failed flush from invocation
    # N must not bleed into invocation N+1.
    _write_buffer = []
    _last_flush_time = time.time()

    # [FIX 3] Wrap entire handler in try/finally so _flush_writes() is
    # guaranteed to run even on exceptions, timeouts, or memory limits.
    try:
        return _handle_event(event, context)
    finally:
        _flush_writes()


def _handle_event(event: Dict, context: Any) -> Dict:
    """Core handler logic, separated for clean try/finally in lambda_handler."""
    global _shadow_update_counter
    _init_aws()
    engine = _load_engine()

    ct_event = event.get("detail", event)
    action = ct_event.get("eventName", "Unknown")

    # --- Noise filter: skip noisy service-to-service actions ---
    if action in NOISE_FILTER_ACTIONS or (NOISE_FILTER_PREFIXES and action.startswith(NOISE_FILTER_PREFIXES)):
        return {"statusCode": 200, "decision": "SKIP", "filtered": True}

    session_id = _resolve_session_id(ct_event)

    # --- Phase 4.1: Check whitelist BEFORE scoring ---
    resource = "*"
    params = ct_event.get("requestParameters") or {}
    if isinstance(params, dict):
        for k in ("bucketName", "tableName", "functionName", "logGroupName"):
            if k in params:
                resource = str(params[k])
                break

    if _is_whitelisted(action, resource):
        logger.info(f"WHITELISTED: {action}|{resource}")
        _emit_metrics("WHITELISTED", 0.0, action)
        return {"statusCode": 200, "decision": "ALLOW", "whitelisted": True}

    # --- Get session context ---
    prev_state = _get_session_state(session_id)
    prev_action = prev_state.get("action") if prev_state else None
    prev_count = int(prev_state.get("count", 0)) if prev_state else 0
    current_count = prev_count + 1
    prev_ts = None
    if prev_state and prev_state.get("timestamp"):
        try:
            prev_ts = datetime.fromisoformat(
                prev_state["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass

    # [FIX 5] Parse the current event timestamp to an aware datetime too,
    # so both prev_ts and curr_ts are the same type. Passing a raw string
    # while prev_ts is a datetime would cause TypeError in time deltas.
    curr_ts = None
    raw_ts = ct_event.get("eventTime", "")
    if raw_ts:
        try:
            curr_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass

    # --- Score (with session-length confidence weighting) ---
    result = engine.evaluate_event(
        prev_action=prev_action,
        curr_event=ct_event,
        prev_timestamp=prev_ts,
        session_event_count=current_count,
    )
    decision = result["decision"]
    phi = result["phi"]

    # --- Item 8: Learning mode ---
    if LEARNING_MODE:
        # [FIX 2] In learning mode: always ALLOW, log scores.
        # Shadow update is intentionally skipped for whitelisted events
        # (the check above already returned early). This prevents an
        # attacker who gets an action whitelisted from poisoning the
        # shadow model.
        session_state = {"prev_action": prev_action, "prev_timestamp": prev_ts}
        _update_shadow(ct_event, session_state)
        _shadow_update_counter += 1
        if _shadow_update_counter % 1000 == 0:
            _save_shadow_periodically()
        logger.info(f"LEARNING: {action} -> phi={phi:.4f} (would be {decision})")
        _buffer_session_update(session_id, action,
                               ct_event.get("eventTime", ""), phi,
                               count=current_count)
        _emit_metrics("LEARNING", phi, action)
        return {
            "statusCode": 200,
            "decision": "ALLOW",
            "learning_mode": True,
            "would_be": decision,
            "phi": phi,
        }

    logger.info(f"SCAPE: {action} -> {decision} (phi={phi:.4f})")

    # --- Phase 4.2+4.3: Update shadow model (only for safe events) ---
    if decision == "ALLOW":
        session_state = {"prev_action": prev_action, "prev_timestamp": prev_ts}
        _update_shadow(ct_event, session_state)
        _shadow_update_counter += 1
        if _shadow_update_counter % 1000 == 0:
            _save_shadow_periodically()

    # --- Buffer session update ---
    _buffer_session_update(
        session_id=session_id,
        action=action,
        timestamp_str=ct_event.get("eventTime", ""),
        score=phi,
        count=current_count,
    )

    # --- Metrics ---
    _emit_metrics(decision, phi, action)

    # --- Alert on anomalies ---
    if decision == "BLOCK":
        _send_alert(ct_event, result, session_id)

    # --- Enforcement ---
    if ENFORCEMENT_MODE == "active" and decision == "BLOCK":
        logger.warning(f"ENFORCEMENT: blocking {action} (phi={phi:.4f})")

    return {
        "statusCode": 200,
        "decision": decision,
        "phi": phi,
        "violations": result["violations"],
    }
