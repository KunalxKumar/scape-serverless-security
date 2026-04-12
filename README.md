# SCAPE: Structural Context-Aware Probabilistic Engine

[![Research Status](https://img.shields.io/badge/Research-Phase--4-blueviolet)](https://github.com/Kunalxkumar/scape-serverless-security)
[![Precision](https://img.shields.io/badge/Precision-1.0-success)](https://github.com/Kunalxkumar/scape-serverless-security)
[![Recall](https://img.shields.io/badge/Recall-1.0-success)](https://github.com/Kunalxkumar/scape-serverless-security)

**SCAPE** is a state-of-the-art anomaly detection engine designed specifically for AWS Lambda environments. It shifts away from generic indicators of compromise (IoC) toward a **structural consistency model** that understands the unique behavioral fingerprint of individual serverless functions.

---

## 🚀 The Core Innovation: C0-C5 Consistency Model

Unlike traditional security tools, SCAPE evaluates every action across six distinct behavioral dimensions:

*   **C0 (Session Context)**: Validates session entry points. Checks if the session-origin (e.g., specific Cognito ID pattern) matches historical normal behavior.
*   **C1 (Transition flow)**: Builds a Markov Chain of event sequences (`A -> B -> C`). If a function suddenly calls `iam:CreateUser` after a `s3:GetObject`, it flags the jump.
*   **C2 (Resource Bound)**: Strictly maps actions to specific ARNs (e.g., a function can read from `bucket-A`, but never `bucket-B`).
*   **C3 (Global Rarity)**: Identifies privilege escalation by flagging actions that are historically rare across the entire account.
*   **C4 (Timing)**: Measures execution latency. Abnormal stalls or bursts can indicate credential exfiltration.
*   **C5 (Data Flow)**: (Experimental) Tracks the volume of data movement to identify mass exfiltration.

---

## 🛠️ How to Use SCAPE "In Real Life" (IRL)

Deploying SCAPE into a real production environment involves a three-stage pipeline.

### Step 1: Data Collection (Learning Phase)
First, you need to gather "Normal" behavior. Enable **AWS CloudTrail** and filter logs for your specific Lambda function roles.

1. Export your CloudTrail logs to S3.
2. Download them locally as JSON.
3. Use the built-in parser to clean them:
   ```bash
   python scripts/parser.py --input raw_cloudtrail.json --output data/logs/real_logs.json
   ```

### Step 2: Training the SCAPE Model
Initialize the engine and feed it the parsed logs to build the internal behavioral graph.
```python
from src.scape_engine import SCAPEEngine

engine = SCAPEEngine()
with open('data/logs/real_logs.json') as f:
    normal_logs = json.load(f)["Records"]

# Train the engine on normal behavior
engine.train_from_logs(normal_logs)
```

### Step 3: Production Inference (Anomaly Detection)
In a real-world setup, you can run SCAPE as a **Security Sidecar** or an **Event-Driven Monitor** (using AWS EventBridge). Every time your Lambda performs an action, SCAPE evaluates it:

```python
# The 'prev_action' comes from your tracking of the current session
evaluation = engine.evaluate_event(prev_action="s3:GetObject", curr_event=new_cloudtrail_record)

if evaluation['decision'] == "BLOCK":
    print(f"🔥 ATTACK DETECTED: {evaluation['violations']}")
    # IRL Action: Automatically revoke the temporary credentials of the sessions
```

---

## 📈 Performance Benchmarks

In our research evaluation using Stratus Red Team attack patterns, SCAPE achieved:

| Metric | Score | Note |
| :--- | :--- | :--- |
| **Precision** | 1.000 | 0 False Positives on normal traffic |
| **Recall** | 1.000 | Caught 100% of Discovery, Persistence, and Exfiltration attacks |
| **F1-Score** | 1.000 | Perfect balance of accuracy and detection |

---

## 📂 Project Structure

- `src/`: The core engine codebase.
- `scripts/`: Data pipeline and attack simulation tools.
- `evaluation/`: Scripts for running ablation studies and performance metrics.
- `data/`: Contains sample datasets for research replication.

## ⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.
