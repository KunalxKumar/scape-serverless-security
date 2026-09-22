"""Build a unified E1/E2/E3 comparison from result JSON files.

Usage:
    python scripts/summarize_recovery_results.py
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _metrics_from_counts(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall) / max(1e-12, precision + recall)
    accuracy = (tp + tn) / max(1, tp + fp + fn + tn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def _extract_cm(result: Dict[str, Any]) -> Tuple[int, int, int, int]:
    cm = result.get("confusion_matrix")
    if isinstance(cm, dict):
        return int(cm.get("tp", 0)), int(cm.get("fp", 0)), int(cm.get("fn", 0)), int(cm.get("tn", 0))

    holdout = result.get("holdout_benign", {})
    attack = result.get("attack_eval", {})
    tp = int(attack.get("block", 0))
    fn = int(attack.get("allow", 0))
    fp = int(holdout.get("block", 0))
    tn = int(holdout.get("allow", 0))
    return tp, fp, fn, tn


def _row(name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    tp, fp, fn, tn = _extract_cm(result)
    metrics = result.get("metrics") or _metrics_from_counts(tp, fp, fn, tn)
    return {
        "experiment": name,
        "domain": result.get("domain", "all"),
        "split": result.get("split", "unknown"),
        "tau": result.get("tau", 0.0),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": float(metrics.get("precision", 0.0)),
        "recall": float(metrics.get("recall", 0.0)),
        "f1": float(metrics.get("f1", 0.0)),
        "accuracy": float(metrics.get("accuracy", 0.0)),
    }


def _pct(x: float) -> str:
    return f"{100.0 * x:.2f}%"


def main() -> None:
    results_dir = os.path.join(BASE_DIR, "results")
    paths = {
        "E1_baseline_hard_veto": os.path.join(results_dir, "paper_data_train_test_e1.json"),
        "E2_mitigated_mixed_domain": os.path.join(results_dir, "paper_data_train_test_e2.json"),
        "E3_mitigated_synthetic_domain": os.path.join(results_dir, "paper_data_train_test_e3.json"),
    }

    rows: List[Dict[str, Any]] = []
    for name, path in paths.items():
        if not os.path.exists(path):
            continue
        rows.append(_row(name, _load_json(path)))

    if not rows:
        raise SystemExit("No experiment result JSON files found.")

    out_json = os.path.join(results_dir, "scape_recovery_comparison.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"rows": rows}, f, indent=2)

    md_lines = [
        "# SCAPE Recovery Evaluation Summary",
        "",
        "| Experiment | Domain | Split | Tau | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        md_lines.append(
            f"| {row['experiment']} | {row['domain']} | {row['split']} | {row['tau']:.4f} | "
            f"{row['tp']} | {row['fp']} | {row['fn']} | {row['tn']} | "
            f"{_pct(row['precision'])} | {_pct(row['recall'])} | {_pct(row['f1'])} | {_pct(row['accuracy'])} |"
        )

    md_lines.extend(
        [
            "",
            "## Interpretation",
            "- E1 reproduces the mixed-domain collapse pattern (all events blocked).",
            "- E2 mitigates collapse and restores benign acceptance on mixed-domain data.",
            "- E3 preserves mitigation under a domain-consistent (synthetic) configuration.",
        ]
    )

    out_md = os.path.join(results_dir, "scape_recovery_summary.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"Wrote {out_json}")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
