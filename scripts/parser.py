import json

def extract_resource(log):
    params = log.get("requestParameters")
    if params is None:
        return "none"
    if "bucketName" in params:
        return "s3://" + params["bucketName"]
    if "roleArn" in params:
        return params["roleArn"]
    return "unknown"

def convert(file):
    with open(file) as f:
        data = json.load(f)
    
    logs = []
    for r in data["Records"]:
        logs.append({
            "event": r.get("eventName"),
            "resource": extract_resource(r)
        })
    return logs

import os

if __name__ == "__main__":
    # Path relative to project root
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_file = os.path.join(base_dir, "data", "logs", "real_logs.json")
    
    if os.path.exists(log_file):
        out = convert(log_file)
        for i in out[:10]:
            print(i)
    else:
        print(f"Error: {log_file} not found")

