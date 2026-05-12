#!/bin/bash
set -euo pipefail

# Store PAM secrets in AWS Secrets Manager
# Usage: ./setup-secrets.sh <aws-region>

REGION="${1:?Usage: $0 <region>}"

echo "=== Storing PAM secrets in AWS Secrets Manager ==="

# Read from env vars (must be set)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
DATABASE_URL="${DATABASE_URL:?Must set DATABASE_URL}"
REDIS_URL="${REDIS_URL:?Must set REDIS_URL}"
ENTRA_TENANT_ID="${ENTRA_TENANT_ID:?Must set ENTRA_TENANT_ID}"
ENTRA_CLIENT_ID="${ENTRA_CLIENT_ID:?Must set ENTRA_CLIENT_ID}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_SSO_INSTANCE_ARN="${AWS_SSO_INSTANCE_ARN:-}"

store_secret() {
    local name="$1"
    local value="$2"

    if [ -z "$value" ]; then
        echo "  Skipping $name (empty)"
        return
    fi

    # Check if secret already exists
    if aws secretsmanager describe-secret --secret-id "pam/$name" --region "$REGION" >/dev/null 2>&1; then
        echo "  Updating existing secret: pam/$name"
        aws secretsmanager put-secret-value \
            --secret-id "pam/$name" \
            --secret-string "$value" \
            --region "$REGION"
    else
        echo "  Creating new secret: pam/$name"
        aws secretsmanager create-secret \
            --name "pam/$name" \
            --secret-string "$value" \
            --region "$REGION"
    fi
}

echo "Storing secrets..."
store_secret "DJANGO_SECRET_KEY" "$DJANGO_SECRET_KEY"
store_secret "DATABASE_URL" "$DATABASE_URL"
store_secret "REDIS_URL" "$REDIS_URL"
store_secret "ENTRA_TENANT_ID" "$ENTRA_TENANT_ID"
store_secret "ENTRA_CLIENT_ID" "$ENTRA_CLIENT_ID"
store_secret "ENTRA_CLIENT_SECRET" "$ENTRA_CLIENT_SECRET"
store_secret "AWS_ACCESS_KEY_ID" "$AWS_ACCESS_KEY_ID"
store_secret "AWS_SECRET_ACCESS_KEY" "$AWS_SECRET_ACCESS_KEY"
store_secret "AWS_SSO_INSTANCE_ARN" "$AWS_SSO_INSTANCE_ARN"

echo ""
echo "=== Done! ==="
echo "Secrets stored under names: pam/NAME"
echo "ECS task definitions reference these via 'secrets' block using the secret name."
echo ""
echo "NOTE: Secrets Manager ARNs include a random suffix (e.g., pam/DJANGO_SECRET_KEY-abc123)."
echo "The ECS task definition uses the secret NAME (not the full ARN) and ECS resolves it."
echo "If you need the full ARN, run:"
echo "  aws secretsmanager describe-secret --secret-id pam/DJANGO_SECRET_KEY --region $REGION --query ARN"
