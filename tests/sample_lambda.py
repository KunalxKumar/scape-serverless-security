"""Sample Lambda function for manifest generator testing."""

import boto3
import json

s3_client = boto3.client('s3')
dynamodb = boto3.client('dynamodb')
logs_client = boto3.client('logs')


def handler(event, context):
    # Read from S3
    response = s3_client.get_object(Bucket='my-app-bucket', Key=event['key'])
    data = response['Body'].read()

    # Write to DynamoDB
    dynamodb.put_item(
        TableName='my-table',
        Item={'id': {'S': event['id']}, 'data': {'S': data.decode()}}
    )

    # Log the event
    logs_client.put_log_events(
        logGroupName='/aws/lambda/myfunc',
        logStreamName='stream-1',
        logEvents=[{'timestamp': 123, 'message': 'processed'}]
    )

    # Sometimes write back to S3
    if event.get('save_result'):
        s3_client.put_object(Bucket='my-app-bucket', Key=f"results/{event['id']}.json",
                             Body=json.dumps({'status': 'done'}))

    return {'statusCode': 200}
