"""Train and test SCAPE using every JSON dataset under the paper ``data/`` tree.

Walks ``data/`` recursively, loads CloudTrail exports and SCAPE-shaped JSON.

**Default split (``--split file``):** trains on all benign JSON except
``test_normal.json`` (holdout) and attack-tagged files (e.g. ``test_anomalous.json``),
evaluates on ``test_normal.json`` and the attack set. This avoids scoring sessions
that never appear in training (which often yield Φ=0 and meaningless thresholds).

**Fallback:** ``--split session`` randomly holds out a fraction of sessions (older behaviour).

Tau is set via F2 calibration on a capped **training** benign prefix plus synthetic
attacks (see ``pipeline/train.py``).

Usage (from ``scape/``)::

    python scripts/train_test_paper_data.py --data-dir ../data
    python scripts/train_test_paper_data.py --data-dir ../data --split session --train-fraction 0.75

Default model path: ``models/paper_data_engine.json``
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.cloudtrail_adapter import _extract_scape_fields  # noqa: E402
from src.scape_engine import SCAPEEngine  # noqa: E402

ATTACK_NAME_PARTS = ("test_anomalous", "anomalous", "attack_logs")


def _rel_norm(rel_path: str) -> str:
    return rel_path.replace("\\", "/")


def is_reserved_benign_test_file(rel_path: str) -> bool:
    """``test_normal.json`` is reserved for evaluation (any subfolder)."""
    lower = _rel_norm(rel_path).lower()
    return lower.endswith("/test_normal.json") or lower == "test_normal.json"


def is_cloudtrail_path(rel_path: str) -> bool:
    lower = _rel_norm(rel_path).lower()
    base = os.path.basename(lower)
    return "/cloudtrail/" in lower or "_cloudtrail_" in base


def is_in_domain(rel_path: str, domain: str) -> bool:
    if domain == "all":
        return True
    if domain == "cloudtrail":
        return is_cloudtrail_path(rel_path)
    if domain == "synthetic":
        return not is_cloudtrail_path(rel_path)
    return True


def _is_raw_cloudtrail_record(rec: Dict[str, Any]) -> bool:
    if not isinstance(rec, dict):
        return False
    if rec.get("eventVersion") is not None:
        return True
    ui = rec.get("userIdentity")
    return isinstance(ui, dict) and len(ui) > 0


def load_events_from_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        records = data.get("Records") or data.get("events") or []
        if not isinstance(records, list):
            records = []
    elif isinstance(data, list):
        records = data
    else:
        return []

    out: List[Dict[str, Any]] = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        if _is_raw_cloudtrail_record(rec):
            out.append(_extract_scape_fields(rec, idx))
        else:
            out.append(rec)
    return out


def collect_json_files(data_dir: str) -> List[str]:
    paths: List[str] = []
    for root, _dirs, files in os.walk(data_dir):
        for name in files:
            if not name.lower().endswith(".json"):
                continue
            paths.append(os.path.join(root, name))
    paths.sort()
    return paths


def is_attack_evaluation_file(rel_path: str) -> bool:
    lower = rel_path.replace("\\", "/").lower()
    return any(part in lower for part in ATTACK_NAME_PARTS)


def group_events_by_session(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    g: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        sid = str(ev.get("sessionId") or "unknown")
        g[sid].append(ev)
    for sid in g:
        g[sid].sort(key=lambda e: e.get("eventTime") or "")
    return dict(g)


def flatten_sessions(session_map: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    ordered: List[Dict[str, Any]] = []
    for sid in sorted(session_map.keys()):
        ordered.extend(session_map[sid])
    return ordered


def flatten_sessions_cap(
    session_map: Dict[str, List[Dict[str, Any]]], max_events: int
) -> List[Dict[str, Any]]:
    """Session-aware stream, stopping after ``max_events`` (for balanced calibration)."""
    if max_events <= 0:
        return []
    out: List[Dict[str, Any]] = []
    for sid in sorted(session_map.keys()):
        for ev in session_map[sid]:
            out.append(ev)
            if len(out) >= max_events:
                return out
    return out


def split_sessions(
    session_ids: List[str], train_fraction: float, seed: int
) -> Tuple[Set[str], Set[str]]:
    rng = random.Random(seed)
    ids = list(session_ids)
    rng.shuffle(ids)
    n_train = int(len(ids) * train_fraction)
    train_ids = set(ids[:n_train])
    test_ids = set(ids[n_train:])
    return train_ids, test_ids


def score_events_by_session(
    engine: SCAPEEngine, session_map: Dict[str, List[Dict[str, Any]]]
) -> Tuple[int, int, List[float]]:
    """Score events with per-session Markov context (matches ``train_from_logs`` / ``pipeline/test``)."""
    phis: List[float] = []
    n_allow = n_block = 0
    for sid in sorted(session_map.keys()):
        prev_a = None
        prev_ts = None
        for ev in session_map[sid]:
            r = engine.evaluate_event(prev_a, ev, prev_timestamp=prev_ts)
            phis.append(r["phi"])
            if r["decision"] == "ALLOW":
                n_allow += 1
            else:
                n_block += 1
            prev_a = ev.get("eventName")
            prev_ts = engine._parse_time(ev.get("eventTime", ""))
    return n_allow, n_block, phis


def compute_binary_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall) / max(1e-12, (precision + recall))
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train/test SCAPE on all paper data/*.json files.")
    parser.add_argument(
        "--data-dir",
        default=os.path.normpath(os.path.join(PROJECT_ROOT, "..", "data")),
        help="Directory containing JSON logs (default: ../data next to scape/)",
    )
    parser.add_argument(
        "--split",
        choices=("file", "session"),
        default="file",
        help="file: hold out test_normal.json; session: random session fraction",
    )
    parser.add_argument(
        "--domain",
        choices=("all", "cloudtrail", "synthetic"),
        default="all",
        help="Dataset domain filter applied before train/test split.",
    )
    parser.add_argument("--train-fraction", type=float, default=0.7, help="Session fraction for training")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for session split")
    parser.add_argument(
        "--output",
        default=os.path.join(PROJECT_ROOT, "models", "paper_data_engine.json"),
        help="Trained model output path",
    )
    parser.add_argument(
        "--results-json",
        default=os.path.join(PROJECT_ROOT, "results", "paper_data_train_test.json"),
        help="Where to write metrics JSON",
    )
    parser.add_argument(
        "--calibration-max-benign",
        type=int,
        default=800,
        help="Max holdout benign events to pass to F2 tau calibration (balance vs. attacks).",
    )
    args = parser.parse_args()

    data_dir = os.path.abspath(args.data_dir)
    if not os.path.isdir(data_dir):
        print(f"Error: data directory not found: {data_dir}")
        raise SystemExit(1)

    all_paths = collect_json_files(data_dir)
    if not all_paths:
        print(f"No JSON files under {data_dir}")
        raise SystemExit(1)

    train_benign_events: List[Dict[str, Any]] = []
    holdout_benign_events: List[Dict[str, Any]] = []
    attack_events: List[Dict[str, Any]] = []
    file_stats: List[Dict[str, Any]] = []
    split_mode = args.split

    for path in all_paths:
        rel = os.path.relpath(path, data_dir)
        if not is_in_domain(rel, args.domain):
            continue
        try:
            events = load_events_from_file(path)
        except (json.JSONDecodeError, OSError, ValueError) as e:
            print(f"  Skip (read error) {rel}: {e}")
            continue
        file_stats.append({"file": rel, "events": len(events)})
        if is_attack_evaluation_file(rel):
            attack_events.extend(events)
        elif split_mode == "file" and is_reserved_benign_test_file(rel):
            holdout_benign_events.extend(events)
        else:
            train_benign_events.extend(events)

    print(f"Data root: {data_dir}")
    print(f"JSON files discovered: {len(all_paths)}")
    print(f"Domain filter: {args.domain}")
    print(f"Split mode: {split_mode}")

    if split_mode == "file" and not holdout_benign_events:
        print("  No test_normal.json found; falling back to --split session.")
        split_mode = "session"
        train_benign_events = []
        holdout_benign_events = []
        attack_events = []
        for path in all_paths:
            rel = os.path.relpath(path, data_dir)
            if not is_in_domain(rel, args.domain):
                continue
            try:
                events = load_events_from_file(path)
            except (json.JSONDecodeError, OSError, ValueError):
                continue
            if is_attack_evaluation_file(rel):
                attack_events.extend(events)
            else:
                train_benign_events.extend(events)
        holdout_benign_events = []

    if split_mode == "session":
        pool = train_benign_events
        if not pool:
            print("Error: no benign events loaded; check JSON structure under data/.")
            raise SystemExit(1)
        benign_by_sid = group_events_by_session(pool)
        session_ids = list(benign_by_sid.keys())
        train_ids, holdout_ids = split_sessions(session_ids, args.train_fraction, args.seed)
        train_events = flatten_sessions({sid: benign_by_sid[sid] for sid in train_ids})
        holdout_benign = flatten_sessions({sid: benign_by_sid[sid] for sid in holdout_ids})
        print(f"Benign events (pooled): {len(pool):,}")
        print(f"Sessions: total={len(session_ids)}, train={len(train_ids)}, holdout={len(holdout_ids)}")
    else:
        train_events = train_benign_events
        holdout_benign = holdout_benign_events
        print(f"Train benign events: {len(train_events):,}")
        print(f"Holdout benign (test_normal): {len(holdout_benign):,}")

    print(f"Attack / labeled anomaly events (test only): {len(attack_events):,}")

    if not train_events:
        print("Error: no training benign events; check JSON structure under data/.")
        raise SystemExit(1)

    print(f"Events: train={len(train_events):,}, holdout benign={len(holdout_benign):,}")

    engine = SCAPEEngine()
    engine.train_from_logs(train_events)

    # F2 calibration on a capped **training** benign prefix + synthetic attacks.
    train_by_sid = group_events_by_session(train_events)
    cal_benign = flatten_sessions_cap(train_by_sid, args.calibration_max_benign)
    holdout_by_sid = group_events_by_session(holdout_benign)
    synthetic_attacks: List[Dict[str, Any]] = []
    for i in range(20):
        synthetic_attacks.append(
            {
                "eventName": f"SyntheticAttack{i}",
                "eventSource": "attack.amazonaws.com",
                "eventTime": "2026-01-01T00:00:00Z",
                "sessionId": f"calibration-attacker-{i}",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "999",
                    "arn": "arn:aws:iam::999:root",
                    "accountId": "999",
                    "accessKeyId": "",
                    "userName": "",
                },
                "requestParameters": {},
            }
        )
    cal_events = cal_benign + synthetic_attacks
    cal_labels = [False] * len(cal_benign) + [True] * len(synthetic_attacks)
    if cal_events:
        engine.calibrate(cal_events, cal_labels)
    print(f"Calibrated tau (F2, {len(cal_benign)} benign + {len(synthetic_attacks)} synthetic): {engine.tau:.6f}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    engine.save(args.output)
    print(f"Model saved to {args.output}")

    if holdout_benign:
        h_allow, h_block, _ = score_events_by_session(engine, holdout_by_sid)
        total_h = max(1, h_allow + h_block)
        print("\n--- Holdout benign (expect mostly ALLOW) ---")
        print(f"  ALLOW: {h_allow:,} ({100 * h_allow / total_h:.2f}%)")
        print(f"  BLOCK: {h_block:,} ({100 * h_block / total_h:.2f}%)")
    else:
        h_allow = h_block = 0
        print("\n--- No holdout benign events (skipped) ---")

    if attack_events:
        attack_by_sid = group_events_by_session(attack_events)
        a_allow, a_block, _ = score_events_by_session(engine, attack_by_sid)
        total_a = max(1, a_allow + a_block)
        print("\n--- Attack / anomaly set (expect mostly BLOCK) ---")
        print(f"  ALLOW: {a_allow:,} ({100 * a_allow / total_a:.2f}%)")
        print(f"  BLOCK: {a_block:,} ({100 * a_block / total_a:.2f}%)")
    else:
        a_allow = a_block = 0
        print("\n--- No attack/anomaly JSON found; skipped attack evaluation ---")

    # Positive class = anomaly/BLOCK
    tp = a_block
    fn = a_allow
    fp = h_block
    tn = h_allow
    binary_metrics = compute_binary_metrics(tp=tp, fp=fp, fn=fn, tn=tn)
    print("\n--- Unified Metrics (positive = anomaly) ---")
    print(f"  TP={tp:,} FP={fp:,} FN={fn:,} TN={tn:,}")
    print(f"  Precision: {100*binary_metrics['precision']:.2f}%")
    print(f"  Recall:    {100*binary_metrics['recall']:.2f}%")
    print(f"  F1:        {100*binary_metrics['f1']:.2f}%")
    print(f"  Accuracy:  {100*binary_metrics['accuracy']:.2f}%")

    session_report: Dict[str, Any]
    if split_mode == "session":
        session_report = {
            "total": len(session_ids),
            "train": len(train_ids),
            "holdout": len(holdout_ids),
        }
    else:
        session_report = {"mode": "file", "note": "holdout = test_normal.json"}

    results = {
        "data_dir": data_dir,
        "split": split_mode,
        "domain": args.domain,
        "notes": [
            "Mixed domains can skew C3. Compare all/cloudtrail/synthetic runs "
            "to validate distribution sensitivity and mitigation behavior.",
        ],
        "train_fraction": args.train_fraction,
        "calibration_benign_events": len(cal_benign),
        "calibration_synthetic_attacks": len(synthetic_attacks),
        "seed": args.seed,
        "files": file_stats,
        "sessions": session_report,
        "events": {
            "train": len(train_events),
            "holdout_benign": len(holdout_benign),
            "attack_eval": len(attack_events),
        },
        "tau": engine.tau,
        "holdout_benign": {"allow": h_allow, "block": h_block},
        "attack_eval": {"allow": a_allow, "block": a_block},
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": binary_metrics,
        "model_path": args.output,
    }
    os.makedirs(os.path.dirname(args.results_json), exist_ok=True)
    with open(args.results_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote results to {args.results_json}")


if __name__ == "__main__":
    main()
