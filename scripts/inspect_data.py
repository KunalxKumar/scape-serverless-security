import json
import os
import csv

def inspect_file(path):
    print(f"\n--- Inspecting {path} ---")
    size = os.path.getsize(path)
    print(f"Size: {size / 1024:.2f} KB")
    
    if path.endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    count = len(data)
                    print(f"Type: JSON List, Count: {count}")
                    if count > 0:
                        print("Sample EventName:", data[0].get("eventName", "N/A"))
                elif isinstance(data, dict):
                    keys = list(data.keys())
                    print(f"Type: JSON Dict, Keys: {keys}")
                    if "Records" in data:
                        print(f"  Records Count: {len(data['Records'])}")
                        if len(data['Records']) > 0:
                            print("  Sample EventName:", data['Records'][0].get("eventName", "N/A"))
                    if "events" in data:
                        print(f"  events Count: {len(data['events'])}")
                else:
                    print(f"Type: JSON {type(data)}")
        except Exception as e:
            print(f"Error: {e}")
    elif path.endswith(".csv"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(next(reader) for _ in range(3))
                print(f"Type: CSV, Sample Columns: {list(rows[0].keys())}")
                print(f"Sample EventName:", rows[0].get("eventName", "N/A"))
        except Exception as e:
            print(f"Error: {e}")

def main():
    data_dir = "data"
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            if f.endswith((".json", ".csv")):
                inspect_file(os.path.join(root, f))

if __name__ == "__main__":
    main()
