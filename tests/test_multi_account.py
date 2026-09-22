"""Quick test for multi-account engine."""
import sys
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from src.multi_account import MultiAccountEngine
from src.scape_engine import SCAPEEngine

# Create multi-account engine
mae = MultiAccountEngine()

# Load our trained engine as account-1
engine = SCAPEEngine.load('models/my_engine.json')
mae.add_account('111111111111', engine)
mae.add_account('222222222222')  # empty account

# Load some test events
with open('data/test_anomalous.json') as f:
    attacks = json.load(f)

print("=== Per-Account Evaluation ===")
for ev in attacks[:5]:
    ev['recipientAccountId'] = '111111111111'
    r = mae.evaluate_event(ev)
    action = ev.get('eventName', 'Unknown')
    print(f"  {action:20s} -> {r['decision']:22s} score={r['anomaly_score']:.2f}")

print("\n=== Cross-Account Detection ===")
# Same session, different accounts
shared_session = attacks[0].get('sessionId', 'cross-test')
for ev in attacks[5:8]:
    ev['recipientAccountId'] = '222222222222'
    ev['sessionId'] = shared_session
    r = mae.evaluate_event(ev)
    action = ev.get('eventName', 'Unknown')
    cross = r['cross_account_alert']
    print(f"  {action:20s} -> {r['decision']:22s} cross_accts={cross['account_count']}  anomalous={cross['is_anomalous']}")

# Stats
stats = mae.get_statistics()
print(f"\n=== Statistics ===")
print(f"  Accounts: {stats['total_accounts']}")
print(f"  Total events: {stats['total_events']}")
print(f"  Cross-account anomalies: {stats['cross_account_anomalies']}")

# Save and reload test
mae.save('models/multi_account_test')
mae2 = MultiAccountEngine.load('models/multi_account_test')
print(f"\n  Reloaded {mae2.account_count} accounts successfully")
