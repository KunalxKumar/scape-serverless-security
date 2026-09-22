import json
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def main():
    log_path = os.path.join(PROJECT_ROOT, "data", "normal_traffic.json")
    model_path = os.path.join(PROJECT_ROOT, "models", "my_engine.json")
    
    print(f"Loading logs from {log_path}...")
    with open(log_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if isinstance(data, dict):
        logs = data.get("Records", [])
    else:
        logs = data
        
    print(f"Training on {len(logs)} events...")
    engine = SCAPEEngine()
    engine.train_from_logs(logs)
    
    # Set a default tau (Step 4 will recalibrate it)
    engine.tau = 0.5
    
    print(f"Saving model to {model_path}...")
    engine.save(model_path)
    print("Done!")

if __name__ == "__main__":
    main()
