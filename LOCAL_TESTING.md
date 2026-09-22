# Local Testing Guide for SCAPE

Before deploying to AWS, all components must pass the local verification suite. This ensures that the engine's mathematical formalism, session tracking, and anomaly detection logic are sound.

## Prerequisites

Ensure you have the following dependencies installed in your Python environment:

```bash
pip install pytest numpy
```

## Running the Suite

The project includes an automation script that runs all verification steps in sequence:

```bash
python scripts/run_local_tests.py
```

This script executes the following:

1.  **Unit Tests (`pytest`)**: 56 tests covering C0–C5 dimensions, Laplace smoothing, and geometric mean aggregation.
2.  **Smoke Tests**: Validates brand-new session handling and privilege escalation veto logic.
3.  **Threshold Calibration**: Trains the engine on `data/normal_traffic.json` and finds the optimal decision threshold (`tau`).
4.  **Full Performance Evaluation**: Measures Precision, Recall, and F1 score against a mixed dataset with a 5% attack ratio.
5.  **Ablation Study**: Investigates which dimensions provide the strongest anomaly signals for current data.

## Interpreting Results

- **FPR (False Positive Rate)**: Targeted at **< 1%** for normal traffic.
- **Recall**: For the Stratus Red Team attack patterns, targeted at **> 90%**.
- **F1 Score**: A balanced metric; should ideally exceed **0.80**.

If any step fails, the script will stop and provide the full error output for debugging.

## Moving to AWS

Once the local suite says `ALL TESTS PASSED`, you can proceed to:
1.  Deploy the Lambda handler in `src/`.
2.  Seed the initial model in DynamoDB.
3.  Enable the CloudTrail trigger.

See `docs/operations.md` for full AWS deployment steps.
