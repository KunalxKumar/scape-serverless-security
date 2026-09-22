# SCAPE AWS Deployment Guide

## Account Info
- **Account**: `630609837381`
- **Region**: `us-east-1`
- **Model Bucket**: `scape-model-630609837381` (to be created)

## Deployment Steps

### Step 1: Create S3 Bucket & Upload Model

```bash
aws s3 mb s3://scape-model-630609837381 --region us-east-1
aws s3 cp models/my_engine.json s3://scape-model-630609837381/scape-model/my_engine.json
```

### Step 2: Create DynamoDB Tables

```bash
# Session state table (with TTL)
aws dynamodb create-table \
  --table-name scape-state \
  --attribute-definitions AttributeName=session_id,AttributeType=S \
  --key-schema AttributeName=session_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

aws dynamodb update-time-to-live \
  --table-name scape-state \
  --time-to-live-specification Enabled=true,AttributeName=ttl

# Whitelist table
aws dynamodb create-table \
  --table-name scape-whitelist \
  --attribute-definitions AttributeName=action_resource,AttributeType=S \
  --key-schema AttributeName=action_resource,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### Step 3: Create Lambda Deployment Package

```bash
cd w:\paper\scape
# Package src/ into a zip
Compress-Archive -Path src\scape_detector.py, src\scape_engine.py, src\session_tracker.py, src\tau_calibrator.py, src\__init__.py -DestinationPath deploy\scape-lambda.zip
```

### Step 4: Create Lambda Function

```bash
aws lambda create-function \
  --function-name scape-detector \
  --runtime python3.12 \
  --handler scape_detector.lambda_handler \
  --role arn:aws:iam::630609837381:role/scape-lambda-role \
  --zip-file fileb://deploy/scape-lambda.zip \
  --timeout 30 \
  --memory-size 512 \
  --environment "Variables={MODEL_BUCKET=scape-model-630609837381,MODEL_KEY=scape-model/my_engine.json,STATE_TABLE=scape-state,WHITELIST_TABLE=scape-whitelist,ENFORCEMENT_MODE=passive}"
```

### Step 5: Create EventBridge Rule

```bash
aws events put-rule \
  --name scape-cloudtrail-trigger \
  --event-pattern '{"source":["aws.s3","aws.iam","aws.sts","aws.lambda","aws.dynamodb","aws.ec2","aws.kms"],"detail-type":["AWS API Call via CloudTrail"]}'

aws events put-targets \
  --rule scape-cloudtrail-trigger \
  --targets "Id=scape-detector,Arn=arn:aws:lambda:us-east-1:630609837381:function:scape-detector"
```

### Step 6: Shadow Mode (7 days)
- Monitor CloudWatch logs for `SCAPE_SHADOW_BLOCK` entries
- Collect phi scores
- Identify false positives and add whitelist entries

### Step 7: Go Live
```bash
aws lambda update-function-configuration \
  --function-name scape-detector \
  --environment "Variables={MODEL_BUCKET=scape-model-630609837381,MODEL_KEY=scape-model/my_engine.json,STATE_TABLE=scape-state,WHITELIST_TABLE=scape-whitelist,ENFORCEMENT_MODE=active}"
```
