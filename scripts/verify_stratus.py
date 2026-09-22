"""Verify Stratus Red Team technique IDs and map them to SCAPE dimensions.

If stratus-red-team CLI is installed, fetches the live technique list.
Otherwise, uses an embedded reference list of known AWS techniques.

Usage:
    python scripts/verify_stratus.py
"""

import json
import shutil
import subprocess
import sys

# Embedded reference: official Stratus Red Team AWS techniques (v2.24)
# Source: https://stratus-red-team.cloud/attack-techniques/list/
STRATUS_TECHNIQUES = [
    {"id": "aws.credential-access.ec2-get-password-data",
     "name": "Retrieve EC2 Password Data",
     "tactic": "Credential Access"},
    {"id": "aws.credential-access.ec2-steal-instance-credentials",
     "name": "Steal EC2 Instance Credentials",
     "tactic": "Credential Access"},
    {"id": "aws.credential-access.secretsmanager-retrieve-secrets",
     "name": "Retrieve a High Number of Secrets Manager secrets",
     "tactic": "Credential Access"},
    {"id": "aws.credential-access.ssm-retrieve-securestring-parameters",
     "name": "Retrieve And Decrypt SSM Parameters",
     "tactic": "Credential Access"},
    {"id": "aws.defense-evasion.cloudtrail-delete",
     "name": "Delete CloudTrail Trail",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.cloudtrail-event-selectors",
     "name": "Disable CloudTrail Logging Through Event Selectors",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.cloudtrail-lifecycle-rule",
     "name": "CloudTrail Logs Impairment Through S3 Lifecycle Rule",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.cloudtrail-stop",
     "name": "Stop CloudTrail Trail",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.dns-delete-logs",
     "name": "Delete DNS query logs",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.organizations-leave",
     "name": "Attempt to Leave the AWS Organization",
     "tactic": "Defense Evasion"},
    {"id": "aws.defense-evasion.vpc-remove-flow-logs",
     "name": "Remove VPC Flow Logs",
     "tactic": "Defense Evasion"},
    {"id": "aws.discovery.ec2-enumerate-from-instance",
     "name": "Execute Discovery Commands on an EC2 Instance",
     "tactic": "Discovery"},
    {"id": "aws.discovery.ec2-download-user-data",
     "name": "Download EC2 Instance User Data",
     "tactic": "Discovery"},
    {"id": "aws.execution.ec2-launch-unusual-instances",
     "name": "Launch Unusual EC2 instances",
     "tactic": "Execution"},
    {"id": "aws.execution.ec2-user-data",
     "name": "Execute Commands on EC2 Instance via User Data",
     "tactic": "Execution"},
    {"id": "aws.exfiltration.ec2-security-group-open-port-22-ingress",
     "name": "Open Ingress Port 22 on a Security Group",
     "tactic": "Exfiltration"},
    {"id": "aws.exfiltration.ec2-share-ami",
     "name": "Exfiltrate an AMI by Sharing It",
     "tactic": "Exfiltration"},
    {"id": "aws.exfiltration.ec2-share-ebs-snapshot",
     "name": "Exfiltrate EBS Snapshot by Sharing It",
     "tactic": "Exfiltration"},
    {"id": "aws.exfiltration.rds-share-snapshot",
     "name": "Exfiltrate RDS Snapshot by Sharing",
     "tactic": "Exfiltration"},
    {"id": "aws.exfiltration.s3-backdoor-bucket-policy",
     "name": "Backdoor an S3 Bucket via its Bucket Policy",
     "tactic": "Exfiltration"},
    {"id": "aws.initial-access.console-login-without-mfa",
     "name": "Console Login without MFA",
     "tactic": "Initial Access"},
    {"id": "aws.lateral-movement.ec2-instance-connect",
     "name": "Usage of EC2 Instance Connect on multiple instances",
     "tactic": "Lateral Movement"},
    {"id": "aws.persistence.iam-backdoor-role",
     "name": "Backdoor an IAM Role",
     "tactic": "Persistence"},
    {"id": "aws.persistence.iam-backdoor-user",
     "name": "Create an Access Key on an IAM User",
     "tactic": "Persistence"},
    {"id": "aws.persistence.iam-create-admin-user",
     "name": "Create an IAM admin user",
     "tactic": "Persistence"},
    {"id": "aws.persistence.iam-create-backdoor-role",
     "name": "Create a backdoored IAM role",
     "tactic": "Persistence"},
    {"id": "aws.persistence.iam-create-user-login-profile",
     "name": "Create a Login Profile on an IAM User",
     "tactic": "Persistence"},
    {"id": "aws.persistence.lambda-backdoor-function",
     "name": "Backdoor Lambda Function Through Resource-Based Policy",
     "tactic": "Persistence"},
    {"id": "aws.persistence.lambda-layer-extension",
     "name": "Add a Malicious Lambda Extension",
     "tactic": "Persistence"},
    {"id": "aws.persistence.lambda-overwrite-code",
     "name": "Overwrite Lambda Function Code",
     "tactic": "Persistence"},
    {"id": "aws.persistence.rolesanywhere-create-trust-anchor",
     "name": "Create an IAM Roles Anywhere trust anchor",
     "tactic": "Persistence"},
]


def map_to_scape_dimension(technique):
    """Map a Stratus technique to its primary SCAPE detection dimension(s)."""
    name_lower = technique["name"].lower()
    tactic = technique["tactic"]

    # Map by tactic + keywords
    if tactic == "Credential Access":
        return "C0 (session) / C3 (rarity)"
    elif tactic == "Initial Access":
        return "C0 (session)"
    elif tactic == "Exfiltration":
        return "C2 (resource) / C5 (data flow)"
    elif tactic == "Persistence":
        if "iam" in name_lower or "user" in name_lower:
            return "C3 (rarity) / C1 (transition)"
        elif "lambda" in name_lower:
            return "C1 (transition) / C3 (rarity)"
        else:
            return "C3 (rarity) / C1 (transition)"
    elif tactic == "Defense Evasion":
        return "C3 (rarity) / C2 (resource)"
    elif tactic == "Discovery":
        return "C4 (timing) / C1 (transition)"
    elif tactic == "Execution":
        return "C1 (transition) / C3 (rarity)"
    elif tactic == "Lateral Movement":
        return "C0 (session) / C4 (timing)"
    else:
        return "Multiple"


def main():
    techniques = STRATUS_TECHNIQUES

    # Try live fetch if stratus CLI is available
    if shutil.which("stratus"):
        try:
            result = subprocess.run(
                ["stratus", "list", "--json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                live = json.loads(result.stdout)
                # Filter to AWS only
                techniques = [t for t in live
                              if t.get("id", "").startswith("aws.")]
                print(f"[LIVE] Fetched {len(techniques)} AWS techniques from stratus CLI\n")
        except Exception as e:
            print(f"[INFO] stratus CLI failed ({e}), using embedded reference list\n")
    else:
        print("[INFO] stratus CLI not found, using embedded reference list\n")

    # Print mapping table
    print(f"{'Technique ID':<60} {'Name':<55} {'SCAPE Dimension'}")
    print("-" * 160)
    for t in sorted(techniques, key=lambda x: x.get("id", "")):
        tid = t.get("id", "")
        name = t.get("name", "")
        dim = map_to_scape_dimension(t)
        print(f"{tid:<60} {name:<55} {dim}")

    print(f"\nTotal AWS techniques mapped: {len(techniques)}")
    print("\nManual step: Compare this table with your paper's taxonomy table")
    print("and correct any mismatches in technique IDs or dimension mappings.")


if __name__ == "__main__":
    main()
