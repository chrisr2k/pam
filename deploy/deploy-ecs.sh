#!/bin/bash
set -euo pipefail

# Deploy PAM to ECS Fargate
# Usage: ./deploy-ecs.sh <aws-region> <account-id> <cluster-name>

REGION="${1:?Usage: $0 <region> <account-id> <cluster-name>}"
ACCOUNT_ID="${2:?Usage: $0 <region> <account-id> <cluster-name>}"
CLUSTER="${3:?Usage: $0 <region> <account-id> <cluster-name>}"

# Step 1: Build and push
echo "=== Building and pushing Docker image ==="
./build-and-push.sh "$REGION" "$ACCOUNT_ID"

# Step 2: Register task definitions
echo "=== Registering ECS task definitions ==="
sed -e "s/ACCOUNT_ID/$ACCOUNT_ID/g" -e "s/REGION/$REGION/g" ecs-task-definition.json > /tmp/pam-web-task.json
sed -e "s/ACCOUNT_ID/$ACCOUNT_ID/g" -e "s/REGION/$REGION/g" ecs-task-definition-celery.json > /tmp/pam-celery-task.json

aws ecs register-task-definition --cli-input-json file:///tmp/pam-web-task.json --region "$REGION"
aws ecs register-task-definition --cli-input-json file:///tmp/pam-celery-task.json --region "$REGION"

# Step 3: Update services
echo "=== Updating ECS services ==="
aws ecs update-service \
    --cluster "$CLUSTER" \
    --service pam-web \
    --task-definition pam-web \
    --force-new-deployment \
    --region "$REGION"

aws ecs update-service \
    --cluster "$CLUSTER" \
    --service pam-celery-worker \
    --task-definition pam-celery-worker \
    --force-new-deployment \
    --region "$REGION"

echo "=== Deployment initiated! ==="
echo "Monitor: aws ecs describe-services --cluster $CLUSTER --services pam-web --region $REGION"
