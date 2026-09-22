import pytest
from src.scape_engine import SCAPEEngine

NORMAL_LOGS = [
    {
        "eventName": "s3:GetObject",
        "requestParameters": {"bucketName": "my-app-bucket"},
        "eventTime": "2026-04-12T01:33:35.000000Z",
        "sessionId": "session-0",
        "additionalEventData": {"bytesTransferredOut": 1024}
    },
    {
        "eventName": "dynamodb:PutItem",
        "requestParameters": {"tableName": "my-table"},
        "eventTime": "2026-04-12T01:33:36.000000Z",
        "sessionId": "session-0",
        "additionalEventData": {"bytesTransferredOut": 10}
    }
]

ANOMALOUS_LOG = {
    "eventName": "s3:GetObject",
    "requestParameters": {"bucketName": "my-app-bucket"},
    "eventTime": "2026-04-12T01:35:00.000000Z",
    "sessionId": "session-0",
    "additionalEventData": {"bytesTransferredOut": 5000000}
}


def test_timing_and_data_flow_anomaly():
    engine = SCAPEEngine()
    engine.train_from_logs(NORMAL_LOGS)

    prev_timestamp = engine._parse_time(NORMAL_LOGS[1]['eventTime'])

    result = engine.evaluate_event(
        prev_action=NORMAL_LOGS[1]['eventName'],
        curr_event=ANOMALOUS_LOG,
        prev_timestamp=prev_timestamp
    )

    # The phi should be lower for anomalous events
    assert 'phi' in result
    assert 'scores' in result
    assert 'violations' in result


def test_transition_n_gram_protection():
    engine = SCAPEEngine()
    engine.train_from_logs(NORMAL_LOGS)

    unexpected = {
        "eventName": "iam:CreateUser",
        "requestParameters": {},
        "eventTime": "2026-04-12T01:33:37.000000Z",
        "sessionId": "session-0",
        "additionalEventData": {"bytesTransferredOut": 0}
    }

    result = engine.evaluate_event(
        prev_action=NORMAL_LOGS[1]['eventName'],
        curr_event=unexpected,
        prev_timestamp=engine._parse_time(NORMAL_LOGS[1]['eventTime'])
    )

    # Unseen transition should produce low C1 score, leading to BLOCK
    assert result['decision'] == 'BLOCK'
    assert result['phi'] < 1.0
