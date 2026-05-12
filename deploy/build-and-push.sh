#!/bin/bash
set -euo pipefail

# Build and push Docker images to Amazon ECR
# Usage: ./build-and-push.sh <aws-region> <account-id>

REGION="${1:-us-east-1}"
ACCOUNT_ID="${2:?Usage: $0 <region> <account-id>}"

REPO_NAME="pam-web"
IMAGE_TAG="latest"

echo "=== Logging into ECR ==="
aws ecr get-login-password --region "$REGION" | \
    docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"

# Create ECR repo if it doesn't exist
aws ecr describe-repositories --repository-names "$REPO_NAME" --region "$REGION" >/dev/null 2>&1 || \
    aws ecr create-repository --repository-name "$REPO_NAME" --region "$REGION" --image-scanning-configuration scanOnPush=true

echo "=== Building Docker image ==="
docker build -t "$REPO_NAME:$IMAGE_TAG" ..

echo "=== Tagging image ==="
docker tag "$REPO_NAME:$IMAGE_TAG" "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$IMAGE_TAG"

echo "=== Pushing to ECR ==="
docker push "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$IMAGE_TAG"

echo "=== Done! ==="
echo "Image: $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$IMAGE_TAG"
