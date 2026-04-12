# scape-serverless-security

**SCAPE: Structural Context-Aware Probabilistic Engine for Serverless Security**

Runtime anomaly detection and adaptive policy enforcement for AWS Lambda functions. Detects "low and slow" attacks that bypass static IAM policies and generic ML detectors.

### Features
- **C0-C5 Consistency Checks**: Multi-dimensional verification of session entry points, transitions, resources, rarity, timing, and data flow.
- **Adaptive Decision Engine**: Automatically shifts from ALLOW to BLOCK based on accumulated surprise/anomaly scores.
- **High Performance**: Achieves perfect Recall (1.0) on standard serverless attack patterns (Discovery, Persistence, Exfiltration).

### Project Structure
- `src/`: Core SCAPE algorithm and engine implementation.
- `scripts/`: Tools for log parsing and attack generation.
- `evaluation/`: Ablation studies and performance measurement scripts.
- `data/`: Sample datasets including normal traffic and simulated anomalies.

### Rapid Start
```bash
python evaluation/run_test.py
```
