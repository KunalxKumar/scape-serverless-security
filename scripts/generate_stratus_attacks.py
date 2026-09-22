"""Generate realistic Stratus Red Team-style attack logs.

These attack sequences use REAL CloudTrail action names (the same ones
seen in normal training data) arranged in patterns that mimic actual
AWS attack techniques. This is critical: the engine must detect
*unusual sequences of allowed actions*, not just unknown actions.

Modeled after MITRE ATT&CK for Cloud and Stratus Red Team techniques:
  https://stratus-red-team.cloud/attack-techniques/AWS/

Attack scenarios:
  1. Credential theft + privilege escalation
  2. S3 data exfiltration
  3. Persistence via access key creation
  4. Discovery / reconnaissance sweep
  5. Defense evasion (trail tampering)
  6. Lateral movement via AssumeRole chains
  7. Lambda backdoor injection
  8. CloudFormation stack manipulation
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
import random

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
random.seed(42)

def ts(base, offset_seconds):
    """Generate ISO timestamp."""
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(action, session_id, time_str, params=None, uid=None):
    ev = {
        "eventName": action,
        "eventTime": time_str,
        "sessionId": session_id,
        "requestParameters": params or {},
    }
    if uid:
        ev["userIdentity"] = uid
    return ev


def generate_stratus_attacks():
    """Generate attacks that use actions present in a real CloudTrail model."""
    attacks = []
    base_time = datetime(2026, 4, 12, 3, 0, 0, tzinfo=timezone.utc)

    # ======================================================================
    # Scenario 1: aws.credential-access.ec2-get-password-data
    # Stolen credentials -> enumerate IAM -> escalate
    # ======================================================================
    sid = "stratus-credtheft-001"
    uid = {"arn": "arn:aws:iam::123456789012:user/compromised-dev",
           "accessKeyId": "AKIA_STOLEN_001"}
    attacks.extend([
        make_event("ConsoleLogin", sid, ts(base_time, 0), uid=uid),
        # Recon: who am I, what can I do?
        make_event("GetCallerIdentity", sid, ts(base_time, 2), uid=uid),
        make_event("ListUsers", sid, ts(base_time, 5), uid=uid),
        make_event("ListRoles", sid, ts(base_time, 8), uid=uid),
        make_event("ListPolicies", sid, ts(base_time, 11), uid=uid),
        make_event("ListAccessKeys", sid, ts(base_time, 14), uid=uid),
        # Privilege escalation: create new admin credentials
        make_event("CreateAccessKey", sid, ts(base_time, 18), uid=uid),
        make_event("AttachUserPolicy", sid, ts(base_time, 22), uid=uid),
        make_event("PutUserPolicy", sid, ts(base_time, 25), uid=uid),
    ])

    # ======================================================================
    # Scenario 2: aws.exfiltration.s3-steal-data
    # AssumeRole -> ListBuckets -> GetObject on sensitive buckets
    # ======================================================================
    sid = "stratus-exfil-002"
    uid = {"arn": "arn:aws:sts::123456789012:assumed-role/ExfilRole/attacker",
           "accessKeyId": "ASIA_EXFIL_002"}
    attacks.extend([
        make_event("AssumeRole", sid, ts(base_time, 60), uid=uid),
        make_event("ListBuckets", sid, ts(base_time, 63),
                   params={"bucketName": "production-secrets"}, uid=uid),
        make_event("GetBucketAcl", sid, ts(base_time, 66),
                   params={"bucketName": "production-secrets"}, uid=uid),
        make_event("GetBucketVersioning", sid, ts(base_time, 68),
                   params={"bucketName": "production-secrets"}, uid=uid),
        make_event("GetBucketLogging", sid, ts(base_time, 70),
                   params={"bucketName": "production-secrets"}, uid=uid),
        # Now access data from an unusual bucket
        make_event("GetObject", sid, ts(base_time, 75),
                   params={"bucketName": "production-secrets", "key": "db-credentials.json"}, uid=uid),
        make_event("GetObject", sid, ts(base_time, 76),
                   params={"bucketName": "production-secrets", "key": "aws-keys.csv"}, uid=uid),
        make_event("GetObject", sid, ts(base_time, 77),
                   params={"bucketName": "production-secrets", "key": "customer-data.tar.gz"}, uid=uid),
    ])

    # ======================================================================
    # Scenario 3: aws.persistence.iam-create-access-key
    # Create backdoor access keys on multiple users
    # ======================================================================
    sid = "stratus-persist-003"
    uid = {"arn": "arn:aws:iam::123456789012:user/admin",
           "accessKeyId": "AKIA_PERSIST_003"}
    attacks.extend([
        make_event("AssumeRole", sid, ts(base_time, 120), uid=uid),
        make_event("ListUsers", sid, ts(base_time, 123), uid=uid),
        make_event("CreateAccessKey", sid, ts(base_time, 126),
                   params={"userName": "service-account-1"}, uid=uid),
        make_event("CreateAccessKey", sid, ts(base_time, 129),
                   params={"userName": "service-account-2"}, uid=uid),
        make_event("CreateAccessKey", sid, ts(base_time, 132),
                   params={"userName": "deploy-bot"}, uid=uid),
        make_event("CreateLoginProfile", sid, ts(base_time, 135),
                   params={"userName": "backdoor-user"}, uid=uid),
    ])

    # ======================================================================
    # Scenario 4: aws.discovery.ec2-enumerate-from-stolen-creds
    # Rapid-fire reconnaissance across multiple services
    # ======================================================================
    sid = "stratus-recon-004"
    uid = {"arn": "arn:aws:iam::123456789012:user/recon-actor",
           "accessKeyId": "AKIA_RECON_004"}
    recon_actions = [
        "DescribeInstances", "DescribeSecurityGroups", "DescribeSubnets",
        "DescribeVpcs", "DescribeVolumes", "DescribeSnapshots",
        "DescribeAddresses", "DescribeKeyPairs", "DescribeImages",
        "DescribeLoadBalancers", "DescribeAlarms", "ListBuckets",
        "DescribeNetworkInterfaces", "DescribeHosts",
        "DescribePlacementGroups", "DescribeDirectories",
    ]
    for i, action in enumerate(recon_actions):
        attacks.append(
            make_event(action, sid, ts(base_time, 180 + i * 2), uid=uid)
        )

    # ======================================================================
    # Scenario 5: aws.defense-evasion.cloudtrail-delete
    # Disable logging to cover tracks
    # ======================================================================
    sid = "stratus-evasion-005"
    uid = {"arn": "arn:aws:iam::123456789012:user/attacker",
           "accessKeyId": "AKIA_EVASION_005"}
    attacks.extend([
        make_event("AssumeRole", sid, ts(base_time, 240), uid=uid),
        make_event("DescribeTrails", sid, ts(base_time, 243), uid=uid),
        make_event("StopLogging", sid, ts(base_time, 246), uid=uid),
        make_event("DeleteTrail", sid, ts(base_time, 249), uid=uid),
        make_event("PutEventSelectors", sid, ts(base_time, 252), uid=uid),
    ])

    # ======================================================================
    # Scenario 6: aws.lateral-movement.ec2-instance-connect
    # Chain of AssumeRole across accounts
    # ======================================================================
    sid = "stratus-lateral-006"
    attacks.extend([
        make_event("AssumeRole", sid, ts(base_time, 300),
                   uid={"arn": "arn:aws:iam::111111111111:role/CrossAccountRole"}),
        make_event("AssumeRole", sid, ts(base_time, 303),
                   uid={"arn": "arn:aws:iam::222222222222:role/TargetRole"}),
        make_event("AssumeRole", sid, ts(base_time, 306),
                   uid={"arn": "arn:aws:iam::333333333333:role/FinalTarget"}),
        make_event("ListBuckets", sid, ts(base_time, 310),
                   uid={"arn": "arn:aws:iam::333333333333:role/FinalTarget"}),
        make_event("GetObject", sid, ts(base_time, 312),
                   params={"bucketName": "target-data"},
                   uid={"arn": "arn:aws:iam::333333333333:role/FinalTarget"}),
    ])

    # ======================================================================
    # Scenario 7: aws.execution.lambda-backdoor
    # Inject malicious code into existing Lambda functions
    # ======================================================================
    sid = "stratus-lambda-007"
    uid = {"arn": "arn:aws:iam::123456789012:user/lambda-attacker",
           "accessKeyId": "AKIA_LAMBDA_007"}
    attacks.extend([
        make_event("AssumeRole", sid, ts(base_time, 360), uid=uid),
        make_event("ListFunctions20150331", sid, ts(base_time, 363), uid=uid),
        make_event("GetFunction20150331v2", sid, ts(base_time, 366), uid=uid),
        make_event("UpdateFunctionCode20150331v2", sid, ts(base_time, 370), uid=uid),
        make_event("UpdateFunctionConfiguration20150331v2", sid, ts(base_time, 374), uid=uid),
        make_event("AddPermission20150331v2", sid, ts(base_time, 378), uid=uid),
        make_event("CreateEventSourceMapping20150331", sid, ts(base_time, 382), uid=uid),
    ])

    # ======================================================================
    # Scenario 8: aws.credential-access.ec2-steal-instance-creds
    # Exploit SSRF to steal EC2 instance metadata credentials
    # ======================================================================
    sid = "stratus-ssrf-008"
    uid = {"arn": "arn:aws:sts::123456789012:assumed-role/EC2InstanceRole/i-0123456789",
           "accessKeyId": "ASIA_SSRF_008"}
    attacks.extend([
        # These are normal EC2 actions but from a suspicious session context
        make_event("DescribeInstances", sid, ts(base_time, 420), uid=uid),
        make_event("DescribeSecurityGroups", sid, ts(base_time, 423), uid=uid),
        # Unusual: instance role accessing IAM
        make_event("ListUsers", sid, ts(base_time, 428), uid=uid),
        make_event("ListRoles", sid, ts(base_time, 431), uid=uid),
        make_event("CreateAccessKey", sid, ts(base_time, 436),
                   params={"userName": "ec2-backdoor"}, uid=uid),
    ])

    return attacks


def main():
    attacks = generate_stratus_attacks()
    output_path = os.path.join(PROJECT_ROOT, "data", "test_anomalous.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(attacks, f, indent=2)

    print(f"Generated {len(attacks)} realistic attack events")
    print(f"Saved to {output_path}")

    # Print summary
    scenarios = {}
    for ev in attacks:
        sid = ev["sessionId"]
        if sid not in scenarios:
            scenarios[sid] = []
        scenarios[sid].append(ev["eventName"])

    print(f"\n{'Scenario':<30} {'Events':>7}  Actions")
    print("-" * 80)
    for sid, actions in scenarios.items():
        label = sid.replace("stratus-", "")
        print(f"  {label:<28} {len(actions):>5}  {' -> '.join(actions[:4])}...")


if __name__ == "__main__":
    main()
