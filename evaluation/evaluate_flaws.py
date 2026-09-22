"""Test script for evaluating the upgraded SCAPE engine on flAWS challenge data.

This script evaluates the formally specified SCAPE engine on flAWS challenge data 
and prints sample detections, the overall detection rate, and the distribution 
of phi scores.
"""

import json
import sys
import os

# Add project root to sys.path so src can be imported.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.scape_engine import SCAPEEngine

def load_logs(filepath):
    """Load a CloudTrail-style JSON file and return its Records list."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        return data.get("Records", [])

if __name__ == "__main__":
    # Baseline: Normal logs for training
    normal_path = os.path.join(PROJECT_ROOT, "data", "logs", "my_cloudtrail_scape.json")
    if not os.path.exists(normal_path):
        normal_path = os.path.join(PROJECT_ROOT, "data", "normal_traffic.json")
    
    normal_logs = load_logs(normal_path)
    
    # Target: flAWS anomalous dataset
    flaws_path = os.path.join(PROJECT_ROOT, "data", "logs", "flaws_sample.json")
    
    if not os.path.exists(flaws_path):
        print(f"Error: flAWS sample data not found at {flaws_path}")
        print("Please run scripts/flaws_adapter.py to generate it from the CSV.")
        sys.exit(1)
        
    flaws_logs = load_logs(flaws_path)
    
    # Create and train engine
    engine = SCAPEEngine()
    print(f"Loading {len(normal_logs)} normal logs for training...")
    engine.train_from_logs(normal_logs)
    
    print("\n=== FLAWS CHALLENGE DATASET TEST ===")
    print(f"Total Events to Evaluate: {len(flaws_logs)}")
    
    detections = 0
    prev_action = None
    prev_ts = None
    
    phi_distribution = {
        "0.00-0.10": 0,
        "0.11-0.25": 0,
        "0.26-0.50": 0,
        "0.51-0.75": 0,
        "0.76-1.00": 0
    }
    
    for i, event in enumerate(flaws_logs):
        res = engine.evaluate_event(prev_action, event, prev_timestamp=prev_ts)
        
        # Track phi distribution
        phi = res['phi']
        if phi <= 0.10: phi_distribution["0.00-0.10"] += 1
        elif phi <= 0.25: phi_distribution["0.11-0.25"] += 1
        elif phi <= 0.50: phi_distribution["0.26-0.50"] += 1
        elif phi <= 0.75: phi_distribution["0.51-0.75"] += 1
        else: phi_distribution["0.76-1.00"] += 1
        
        if res['decision'] != "ALLOW":
            detections += 1
            if detections <= 10: # Sample first 10 alerts
                print(f"[{i}] DETECTED: {event.get('eventName')} - Phi: {phi:.4f} - Violated: {res['violations']}")
                
        prev_action = event.get('eventName')
        prev_ts = engine._parse_time(event.get("eventTime", ""))
    
    print("-" * 45)
    print(f"Overall Anomaly Detection Rate: {detections/len(flaws_logs)*100:.2f}%")
    print(f"Total Anomalies Flagged: {detections} out of {len(flaws_logs)}")
    print("\nPhi Score Distribution:")
    for k, v in phi_distribution.items():
        print(f"  {k}: {v:>5} events ({v/len(flaws_logs)*100:.1f}%)")
