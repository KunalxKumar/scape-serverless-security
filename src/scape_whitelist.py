"""Phase 4.1: Whitelist Lambda handler.

Provides an API endpoint for marking actions as confirmed benign.
Called via API Gateway when a human reviews an alert and clicks
"Mark as Benign".
"""

import json
import os
import logging

logger = logging.getLogger("scape-whitelist")
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Handle whitelist API requests.

    POST /whitelist
      Body: {"action": "AssumeRole", "resource": "*"}
      -> Adds to whitelist

    POST /whitelist
      Body: {"action": "AssumeRole", "resource": "*", "remove": true}
      -> Removes from whitelist
    """
    import boto3

    table_name = os.environ.get("WHITELIST_TABLE", "scape-whitelist")
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)

    try:
        body = json.loads(event.get("body", "{}"))
    except (json.JSONDecodeError, TypeError):
        return _response(400, {"error": "Invalid JSON body"})

    action = body.get("action")
    resource = body.get("resource", "*")

    if not action:
        return _response(400, {"error": "Missing 'action' field"})

    key = f"{action}|{resource}"

    if body.get("remove"):
        # Remove from whitelist
        table.delete_item(Key={"action_resource": key})
        logger.info(f"Removed from whitelist: {key}")
        return _response(200, {"message": f"Removed {key} from whitelist"})
    else:
        # Add to whitelist
        table.put_item(Item={
            "action_resource": key,
            "action": action,
            "resource": resource,
            "added_by": body.get("added_by", "manual"),
            "reason": body.get("reason", ""),
        })
        logger.info(f"Added to whitelist: {key}")
        return _response(200, {"message": f"Added {key} to whitelist"})


def _response(code, body):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
