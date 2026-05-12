#!/bin/bash
set -euo pipefail

# Start PAM demo environment
# Usage: ./demo-start.sh [local|ecs] [region] [account-id] [cluster-name]

MODE="${1:-local}"

if [ "$MODE" = "ecs" ]; then
    # ECS mode - scale services up
    REGION="${2:?Usage: ./demo-start.sh ecs <region> <account-id> <cluster-name>}"
    ACCOUNT_ID="${3:?Usage: ./demo-start.sh ecs <region> <account-id> <cluster-name>}"
    CLUSTER="${4:?Usage: ./demo-start.sh ecs <region> <account-id> <cluster-name>}"

    echo "=== Starting PAM Demo on ECS ==="

    # Scale web service to 1
    echo "Scaling web service to 1..."
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service pam-web \
        --desired-count 1 \
        --region "$REGION" > /dev/null

    # Scale celery worker to 1
    echo "Scaling celery worker to 1..."
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service pam-celery-worker \
        --desired-count 1 \
        --region "$REGION" > /dev/null

    echo "Waiting for services to stabilize..."
    aws ecs wait services-stable \
        --cluster "$CLUSTER" \
        --services pam-web pam-celery-worker \
        --region "$REGION"

    # Get the ALB URL
    ALB_DNS=$(aws elbv2 describe-load-balancers \
        --names pam-alb \
        --region "$REGION" \
        --query 'LoadBalancers[0].DNSName' \
        --output text)

    echo ""
    echo "=== PAM Demo is LIVE ==="
    echo "URL: https://$ALB_DNS"
    echo ""
    echo "To stop: ./demo-stop.sh ecs $REGION $ACCOUNT_ID $CLUSTER"

else
    # Local mode - use docker-compose
    echo "=== Starting PAM Demo Locally ==="

    cd "$(dirname "$0")/.."

    # Check if .env exists
    if [ ! -f .env ]; then
        echo "ERROR: No .env file found. Copy .env.example to .env and configure it."
        echo "  cp .env.example .env"
        echo "  # Then edit .env with your Entra ID credentials"
        exit 1
    fi

    # Start services
    echo "Starting Docker Compose services..."
    docker compose up -d

    echo "Waiting for web service to be ready..."
    for i in $(seq 1 30); do
        if curl -s http://localhost:8080/ > /dev/null 2>&1; then
            break
        fi
        sleep 2
    done

    echo ""
    echo "=== PAM Demo is running locally ==="
    echo "Local URL: http://localhost:8080"
    echo ""
    echo "Demo accounts (created automatically on first run):"
    echo "  Admin:     admin / admin123"
    echo "  Approver:  approver / approver123"
    echo "  Requester: requester / requester123"
    echo ""

    # Check if ngrok is available
    if command -v ngrok &> /dev/null; then
        echo "Starting ngrok tunnel for public access..."
        echo "Press Ctrl+C to stop the tunnel when done."
        echo ""
        ngrok http 8080 --log=stdout 2>/dev/null || \
        ngrok http 8080
    else
        echo "To expose this to the internet, install ngrok and run:"
        echo "  ngrok http 8080"
        echo ""
        echo "To stop: docker compose down"
    fi
fi
