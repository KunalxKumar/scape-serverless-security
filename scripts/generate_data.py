import json
import random
import os
from datetime import datetime, timedelta

def generate_normal_logs(count=100):
    logs = []
    base_time = datetime.now()
    for i in range(count):
        session = f"session-{i//3}"
        events = [
            {"eventName": "s3:GetObject", "requestParameters": {"bucketName": "my-app-bucket"}},
            {"eventName": "dynamodb:PutItem", "requestParameters": {"tableName": "my-table"}},
            {"eventName": "logs:PutLogEvents", "requestParameters": {"logGroupName": "/aws/lambda/myfunc"}}
        ]
        t = base_time + timedelta(seconds=i*2)
        for j, ev in enumerate(events):
            ev_copy = ev.copy()
            ev_copy["eventTime"] = (t + timedelta(milliseconds=j*500)).isoformat() + "Z"
            ev_copy["sessionId"] = session
            logs.append(ev_copy)
    return logs

def generate_attack_logs(count=20):
    logs = []
    base_time = datetime.now()
    for i in range(count):
        session = f"attacker-{i}"
        # Normal start
        logs.append({"eventName": "s3:GetObject", "requestParameters": {"bucketName": "my-app-bucket"}, "eventTime": base_time.isoformat()+"Z", "sessionId": session})
        # Malicious action
        attack_action = random.choice(["s3:DeleteBucket", "iam:CreateUser", "dynamodb:DeleteTable"])
        logs.append({"eventName": attack_action, "requestParameters": {}, "eventTime": (base_time+timedelta(seconds=1)).isoformat()+"Z", "sessionId": session})
    return logs

os.makedirs("data", exist_ok=True)

with open("data/normal_traffic.json", "w") as f:
    json.dump(generate_normal_logs(100), f, indent=2)

with open("data/test_normal.json", "w") as f:
    json.dump(generate_normal_logs(30), f, indent=2)

with open("data/test_anomalous.json", "w") as f:
    json.dump(generate_attack_logs(20), f, indent=2)

print("Data generated in data/ folder")
