from src.scape_engine import SCAPEEngine

class scape:
    def __init__(self):
        self.engine = SCAPEEngine()
    
    def train(self, logs):
        self.engine.train_from_logs(logs)
    
    def check(self, prev, curr):
        result = self.engine.evaluate_event(prev, curr)
        return result["decision"], result["anomaly_score"], result["violations"]
