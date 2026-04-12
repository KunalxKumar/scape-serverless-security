import json
import os
import sys

# Add project root to path so we can import src
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from src.engine import scape

def load(file):
    with open(file) as f:
        data = json.load(f)
        if isinstance(data, dict) and "Records" in data:
            return data["Records"]
        return data

def evaluate(model, logs, is_attack):
    prev = None
    tp = fp = tn = fn = 0

    for l in logs:
        d, sc, iss = model.check(prev, l)
        
        # In our case, ANY decision other than "ALLOW" is considered a detection
        # Note: Decision strings in scape_engine are uppercase: "ALLOW", "BLOCK", etc.
        pred_attack = d.upper() != "ALLOW"

        if pred_attack and is_attack:
            tp += 1
        elif pred_attack and not is_attack:
            fp += 1
        elif not pred_attack and not is_attack:
            tn += 1
        elif not pred_attack and is_attack:
            fn += 1

        prev = l["eventName"]

    precision = tp/(tp+fp) if (tp+fp)>0 else 0
    recall = tp/(tp+fn) if (tp+fn)>0 else 0
    f1 = (2*precision*recall)/(precision+recall) if (precision+recall)>0 else 0

    return precision, recall, f1, tp, fp, tn, fn

if __name__ == "__main__":
    # Correct paths relative to script
    normal_path = os.path.join(project_root, "data", "logs", "real_logs.json")
    attack_path = os.path.join(project_root, "data", "logs", "attack_logs.json")

    normal = load(normal_path)
    attack = load(attack_path)

    model = scape()
    model.train(normal)

    print("=== NORMAL DATA ===")
    p, r, f1, tp, fp, tn, fn = evaluate(model, normal, False)
    print(f"precision: {p:.4f} recall: {r:.4f} f1: {f1:.4f}")
    print(f"Metrics: TP={tp}, FP={fp}, TN={tn}, FN={fn}")

    print("\n=== ATTACK DATA ===")
    p, r, f1, tp, fp, tn, fn = evaluate(model, attack, True)
    print(f"precision: {p:.4f} recall: {r:.4f} f1: {f1:.4f}")
    print(f"Metrics: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
