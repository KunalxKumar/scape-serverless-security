# SCAPE Operations Guide

## Overview

SCAPE (Structural Context-Aware Probabilistic Engine) detects anomalous AWS API usage by building a behavioral model from CloudTrail logs and scoring incoming events against six consistency checks (C0-C5).

---

## 1. Training a Model

### 1.1 Fetch CloudTrail Logs

```bash
# Fetch up to 500,000 events from your AWS account
python scripts/fetch_cloudtrail_simple.py --max-events 500000 --output data/logs/training_logs.json
```

Aim for **7-30 days** of clean (no known attacks) production activity.

### 1.2 Train the Engine

```bash
python train_my_logs.py
```

This produces `models/my_engine.json` containing:
- Learned transitions (C1)
- Known resources (C2)
- Action frequency baselines (C3)
- Timing statistics (C4)
- Data flow baselines (C5)

### 1.3 Verify Training

```bash
python evaluate_my_model.py --flaws-limit 1000
```

Expected output:
```
Synthetic attack detection: 40/40 (100%)
flAWS detection: ~92% detected
```

---

## 2. Calibrating Thresholds

Thresholds should be set from percentiles of **your own normal traffic**, not defaults.

```bash
# Compute percentiles and optionally save to model
python evaluation/calibrate_thresholds.py --save

# With custom FPR ceiling
python evaluation/calibrate_thresholds.py --fpr-ceiling 0.005 --save
```

This sets:
| Threshold | Percentile | Target FPR |
|:---|:---|:---|
| `threshold_alert` | P99 | ~1% |
| `threshold_restrict` | P99.9 | ~0.1% |
| `threshold_block` | P99.99 | ~0.01% |

You can also override weights at runtime:
```bash
export SCAPE_WEIGHTS="0.20,0.20,0.30,0.15,0.10,0.20"
```

---

## 3. Deployment

### 3.1 Prerequisites

- AWS SAM CLI installed
- AWS credentials configured
- Trained model uploaded to S3:

```bash
aws s3 cp models/my_engine.json s3://your-bucket/scape-model/my_engine.json
```

### 3.2 Deploy

```bash
sam build
sam deploy --guided \
  --parameter-overrides \
    EnforcementMode=passive \
    AlertEmail=security@yourcompany.com \
    ModelBucket=your-bucket \
    ModelKey=scape-model/my_engine.json \
    ThresholdAlert=2.0 \
    ThresholdRestrict=6.25 \
    ThresholdBlock=12.5
```

### 3.3 Deployment Modes

| Mode | Behavior |
|:---|:---|
| `passive` | Score events, emit metrics, send alerts. No blocking. |
| `active` | All passive actions + invoke enforcer for BLOCK decisions. |

**Recommendation**: Always start in `passive` mode for at least 1 week.

---

## 4. Monitoring

### 4.1 CloudWatch Dashboard

After deployment, visit the dashboard at:
```
https://<region>.console.aws.amazon.com/cloudwatch/home#dashboards:name=<stack-name>-monitoring
```

Key metrics:
- **AnomalyScore (avg/max/p99)**: Tracks baseline score drift
- **Decision Distribution**: Monitors ALLOW vs ALERT vs BLOCK ratios
- **Lambda Duration**: Ensures detector is fast (<100ms target)

### 4.2 Alert Response

When you receive an SNS alert:

1. **Review the event**: Check the action, session, and violations
2. **If benign**: Add to whitelist via API:
   ```bash
   curl -X POST https://<api-endpoint>/whitelist \
     -d '{"action": "AssumeRole", "resource": "*"}'
   ```
3. **If malicious**: Investigate the session for lateral movement

---

## 5. Online Learning (Shadow Model)

SCAPE supports continuous adaptation via guarded online learning:

```python
from src.guarded_learning import GuardedLearningEngine

# Load
gle = GuardedLearningEngine.load("models/guarded/")

# Process events (shadow learns automatically)
for event in new_events:
    result = gle.evaluate(event)

# Weekly review
review = gle.get_shadow_review()
print(f"New actions learned: {review['new_actions_count']}")
print(f"New transitions: {review['new_transitions_count']}")

# If review looks safe, promote
gle.promote_shadow()
gle.save("models/guarded/")
```

**Rules:**
- Shadow only learns from ALLOW events (Phase 4.3)
- Never auto-promote; always require human review
- Reject shadow if unexpected actions appear

---

## 6. Manifest Generator (CI/CD Integration)

### 6.1 Generate Manifest

```bash
# Single file
python src/static_analyzer.py lambda_function.py -o manifest.json

# Entire directory
python src/static_analyzer.py ./lambda_package/ -o manifest.json

# Validate against trained model
python src/static_analyzer.py lambda_function.py --validate models/my_engine.json
```

### 6.2 GitHub Actions Integration

```yaml
# .github/workflows/scape-manifest.yml
name: SCAPE Manifest Check
on: [pull_request]
jobs:
  check-manifest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: python src/static_analyzer.py src/ -o manifest.json
      - run: git diff --exit-code manifest.json
        name: Verify manifest unchanged
```

---

## 7. Multi-Account Setup

```python
from src.multi_account import MultiAccountEngine

# Train from multi-account logs
mae = MultiAccountEngine()
mae.train_from_multi_account_logs(logs, account_field="recipientAccountId")

# Cross-account detection
result = mae.evaluate_event(event)
if result["cross_account_alert"]["is_anomalous"]:
    print(f"Session spans {result['cross_account_alert']['account_count']} accounts!")

# Save/load
mae.save("models/multi_account/")
mae = MultiAccountEngine.load("models/multi_account/")
```

---

## 8. Troubleshooting

### High False-Positive Rate

```bash
python evaluation/fp_analysis.py
```

Common fixes:
- **C3 (Rarity)**: Train on more diverse logs or lower `rarity_threshold`
- **C1 (Transition)**: Increase smoothing `alpha` or train longer
- **C0 (Session)**: Expand training to cover more session prefixes

### Model Drift

Re-calibrate thresholds monthly:
```bash
python evaluation/calibrate_thresholds.py --save
```

### Lambda Cold Starts

The detector caches the model in `/tmp` after the first S3 download. Subsequent invocations load from cache (~50ms vs ~500ms from S3).

---

## 9. Architecture

```
EventBridge Rule
     |
     v
[SCAPE Detector Lambda]
     |
     +-- Loads model from S3 (cached in /tmp)
     +-- Reads session state from DynamoDB
     +-- Scores event (C0-C5 checks)
     +-- Emits CloudWatch metrics
     +-- Sends SNS alert (if anomalous)
     +-- Batches session updates to DynamoDB
     |
     +-- (active mode) Invokes Enforcer Lambda
```
