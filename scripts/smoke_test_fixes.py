import json
import os
import sys
import traceback

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from src.scape_engine import SCAPEEngine

print("Running Local Smoke Test for Fixes 1 & 2...")

# Create and train an engine with synthetic data so we have the right prefixes
engine = SCAPEEngine()
synthetic_logs = [
    {
        "eventName": "s3:GetObject",
        "requestParameters": {"bucketName": "my-app-bucket"},
        "sessionId": "cognito-us-east-1:known-session",
        "eventTime": "2026-04-14T00:00:00Z"
    }
]
engine.train_from_logs(synthetic_logs)

try:
    print("Test 1: Fix 1 - brand new session from known prefix should NOT hard-block")
    result = engine.evaluate_event(
        prev_action="s3:GetObject",
        curr_event={
            "eventName": "s3:GetObject",
            "requestParameters": {"bucketName": "my-app-bucket"},
            "sessionId": "cognito-us-east-1:new-session-999",  # known prefix, unseen ID
            "eventTime": "2026-04-15T10:00:00Z"
        }
    )
    assert result["decision"] == "ALLOW", f"Fix 1 regression: new legit session blocked - {result}"
    print("   [+] Test 1 passed!")

    print("Test 2: Fix 2 - privilege escalation must veto even with all other dims clean")
    result = engine.evaluate_event(
        prev_action="s3:GetObject",
        curr_event={
            "eventName": "iam:CreateUser",
            "requestParameters": {"bucketName": "my-app-bucket"},
            "sessionId": "cognito-us-east-1:known-session",
            "eventTime": "2026-04-15T10:00:01Z"
        }
    )
    assert result["decision"] == "BLOCK", f"Fix 2 regression: privesc not vetoed - {result}"
    print("   [+] Test 2 passed!")

    print("\nAll smoke tests passed successfully! The weighted Phi wiring is solid.")

except AssertionError as e:
    print(f"\n[!] Smoke test failed: {e}")
except Exception as e:
    print(f"\n[!] Unexpected error:")
    traceback.print_exc()
