#!/bin/bash
set -euo pipefail

# Store PAM secrets in AWS SSM Parameter Store
# Usage: ./setup-ssm-params.sh <aws-region>

REGION="${1:?Usage: $0 <region>}"

echo "=== Storing PAM secrets in SSM Parameter Store ==="

# Prompt for each secret (or read from env vars)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
DATABASE_URL="${DATABASE_URL:?Must set DATABASE_URL}"
REDIS_URL="${REDIS_URL:?Must set REDIS_URL}"
ENTRA_TENANT_ID="${ENTRA_TENANT_ID:?Must set ENTRA_TENANT_ID}"
ENTRA_CLIENT_ID="${ENTRA_CLIENT_ID:?Must set ENTRA_CLIENT_ID}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_SSO_INSTANCE_ARN="${AWS_SSO_INSTANCE_ARN:-}"

store_param() {
    local name="$1"
    local value="$2"
    local type="${3:-SecureString}"

    if [ -z "$value" ]; then
        echo "  Skipping $name (empty)"
        return
    fi

    aws ssm put-parameter \
        --name "/pam/$name" \
        --value "$value" \
        --type "$type" \
        --overwrite \
        --region "$REGION"

    echo "  Stored /pam/$name"
}

echo "Storing parameters..."
store_param "DJANGO_SECRET_KEY" "$DJANGO_SECRET_KEY"
store_param "DATABASE_URL" "$DATABASE_URL"
store_param "REDIS_URL" "$REDIS_URL"
store_param "ENTRA_TENANT_ID" "$ENTRA_TENANT_ID" "String"
store_param "ENTRA_CLIENT_ID" "$ENTRA_CLIENT_ID" "String"
store_param "ENTRA_CLIENT_SECRET" "$ENTRA_CLIENT_SECRET"
store_param "AWS_ACCESS_KEY_ID" "$AWS_ACCESS_KEY_ID" "String"
store_param "AWS_SECRET_ACCESS_KEY" "$AWS_SECRET_ACCESS_KEY"
store_param "AWS_SSO_INSTANCE_ARN" "$AWS_SSO_INSTANCE_ARN" "String"

echo "=== Done! ==="
