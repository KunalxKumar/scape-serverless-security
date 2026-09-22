"""Fix 4: Rolling Recalibration Utility.

Tracks emitted Phi scores from production traffic over time and recalibrates
the engine threshold (tau) dynamically to account for environmental drift.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
import os


class TauCalibrator:
    def __init__(self, phi_log_path: str, target_fpr: float = 0.01):
        self.phi_log_path = Path(phi_log_path)
        self.target_fpr = target_fpr

        # Ensure directory exists
        if not self.phi_log_path.parent.exists():
            self.phi_log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_phi(self, phi: float, label: str = "normal"):
        """Call this on every evaluated event in production.
        
        Appends the score to a rolling log file.
        """
        with open(self.phi_log_path, 'a', encoding="utf-8") as f:
            f.write(json.dumps({"phi": phi, "label": label,
                                "ts": datetime.utcnow().isoformat()}) + "\n")

    def recalibrate(self, lookback_days: int = 30) -> float:
        """Recompute tau from recent normal-traffic Phi scores.
        
        Args:
            lookback_days: Determine the time-window of logs to include.
            
        Returns:
            The newly calculated optimal tau float.
        """
        if not self.phi_log_path.exists():
            raise FileNotFoundError(f"Phi log not found at {self.phi_log_path}")

        cutoff = datetime.utcnow() - timedelta(days=lookback_days)
        phis = []
        
        with open(self.phi_log_path, 'r', encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("label") == "normal" and rec.get("ts", "") > cutoff.isoformat():
                        phis.append(rec["phi"])
                except json.JSONDecodeError:
                    pass

        if len(phis) < 100:
            raise ValueError(f"Only {len(phis)} samples found. Need at least 100 normal-traffic samples to recalibrate safely.")

        phis.sort()
        # tau = the Phi value below which only target_fpr % of normal traffic falls
        cutoff_idx = int(len(phis) * self.target_fpr)
        new_tau = phis[max(0, min(cutoff_idx, len(phis)-1))]
        return new_tau
