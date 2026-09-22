import csv
import json
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

def convert_flaws_csv_to_scape(input_csv, output_json, limit=None):
    """
    Parses the flAWS CSV and extracts relevant SCAPE fields.
    Mapping:
    - eventName -> eventName
    - eventTime -> eventTime
    - userIdentityprincipalId -> sessionId (as a proxy)
    - sourceIPAddress -> sourceIp (additional context)
    - requestParametersinstanceType -> requestParameters (placeholder for resource)
    """
    records = []
    try:
        with open(input_csv, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if limit is not None and i >= limit:
                    break
                
                # Cleaning/Adapting fields
                record = {
                    "eventName": row.get("eventName", "unknown"),
                    "eventTime": row.get("eventTime", ""),
                    "sessionId": row.get("userIdentityprincipalId", "unknown"),
                    "sourceIPAddress": row.get("sourceIPAddress", "unknown"),
                    "userAgent": row.get("userAgent", "unknown"),
                    "requestParameters": {}, # flAWS CSV mapping is a bit opaque for resources
                    "recipientAccountId": row.get("userIdentityaccountId", "unknown")
                }
                
                # Mock resource if possible (e.g. if it's an S3 call)
                if "s3" in record["eventName"].lower():
                    # Placeholders for C2 check
                    record["requestParameters"]["bucketName"] = "flaws-bucket"
                
                records.append(record)
        
        with open(output_json, 'w') as f:
            json.dump({"Records": records}, f, indent=2)
            
        print(f"Successfully converted {len(records)} records to {output_json}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    csv_path = os.path.join(PROJECT_ROOT, "data", "logs", "flaws", "dec12_18features.csv")
    out_json = os.path.join(PROJECT_ROOT, "data", "logs", "flaws_sample.json")
    
    if os.path.exists(csv_path):
        # Convert first 5000 records for evaluation
        convert_flaws_csv_to_scape(csv_path, out_json, limit=None)   # or a big number like 100000
    else:
        print(f"Dataset not found at {csv_path}")
