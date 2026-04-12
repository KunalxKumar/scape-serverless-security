import json
import os

def generate_attack_logs():
    """Generates simulated attack logs based on Stratus Red Team techniques."""
    attacks = [
        {
            "eventVersion": "1.08",
            "eventTime": "2026-04-12T10:00:00Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "GetCallerIdentity",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "userAgent": "attacker-cli",
            "requestParameters": None,
            "notes": "Discovery: Reconnaissance after initial access"
        },
        {
            "eventVersion": "1.08",
            "eventTime": "2026-04-12T10:05:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "requestParameters": {"userName": "backdoor-user"},
            "notes": "Persistence: Creating a backdoor user"
        },
        {
            "eventVersion": "1.08",
            "eventTime": "2026-04-12T10:10:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "notes": "Discovery: Listing S3 buckets"
        },
        {
            "eventVersion": "1.08",
            "eventTime": "2026-04-12T10:15:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "requestParameters": {"bucketName": "sensitive-data-630609837381", "key": "credentials.csv"},
            "notes": "Exfiltration: Downloading sensitive files"
        },
        {
            "eventVersion": "1.08",
            "eventTime": "2026-04-12T10:20:00Z",
            "eventSource": "lambda.amazonaws.com",
            "eventName": "UpdateFunctionCode",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "requestParameters": {"functionName": "prod-processor"},
            "notes": "Persistence/Impact: Modifying Lambda function code"
        }
    ]
    
    data = {"Records": attacks}
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(base_dir, "data", "logs", "attack_logs.json")
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Attack logs generated at: {output_path}")
    return data

if __name__ == "__main__":
    generate_attack_logs()
