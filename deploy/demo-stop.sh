#!/bin/bash
set -euo pipefail

# Stop PAM demo environment
# Usage: ./demo-stop.sh [local|ecs] [region] [account-id] [cluster-name]

MODE="${1:-local}"

if [ "$MODE" = "ecs" ]; then
    # ECS mode - scale services to zero
    REGION="${2:?Usage: ./demo-stop.sh ecs <region> <account-id> <cluster-name>}"
    ACCOUNT_ID="${3:?Usage: ./demo-stop.sh ecs <region> <account-id> <cluster-name>}"
    CLUSTER="${4:?Usage: ./demo-stop.sh ecs <region> <account-id> <cluster-name>}"

    echo "=== Stopping PAM Demo on ECS ==="

    # Scale web service to 0
    echo "Scaling web service to 0..."
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service pam-web \
        --desired-count 0 \
        --region "$REGION" > /dev/null

    # Scale celery worker to 0
    echo "Scaling celery worker to 0..."
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service pam-celery-worker \
        --desired-count 0 \
        --region "$REGION" > /dev/null

    echo ""
    echo "=== PAM Demo stopped ==="
    echo "ECS services scaled to 0. No Fargate costs."
    echo "ALB, RDS, and Redis are still running (baseline ~$54/mo)."
    echo ""
    echo "To restart: ./demo-start.sh ecs $REGION $ACCOUNT_ID $CLUSTER"

else
    # Local mode - stop docker-compose
    echo "=== Stopping PAM Demo Locally ==="

    cd "$(dirname "$0")/.."

    echo "Stopping Docker Compose services..."
    docker compose down

    echo ""
    echo "=== PAM Demo stopped ==="
    echo "All containers stopped and removed."
    echo ""
    echo "To restart: ./demo-start.sh"
fi
