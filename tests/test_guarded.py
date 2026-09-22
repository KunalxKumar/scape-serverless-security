"""Quick test for guarded learning engine."""
import sys, os, json
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from src.guarded_learning import GuardedLearningEngine
from src.scape_engine import SCAPEEngine

engine = SCAPEEngine.load('models/my_engine.json')
gle = GuardedLearningEngine(live_engine=engine)

with open('data/test_normal.json') as f:
    events = json.load(f)

for ev in events[:20]:
    r = gle.evaluate(ev)

review = gle.get_shadow_review()
print('Shadow Review:')
print(f'  Events learned: {review["events_learned"]}')
print(f'  New actions: {review["new_actions_count"]}')
print(f'  New transitions: {review["new_transitions_count"]}')
print(f'  Alerts: {review["recent_alerts"]}')

gle.save('models/guarded_test')
gle2 = GuardedLearningEngine.load('models/guarded_test')
print(f'Reloaded OK. Whitelist size: {len(gle2.whitelist)}')
