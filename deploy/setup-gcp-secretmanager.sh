#!/bin/bash
set -euo pipefail

# Store PAM secrets in GCP Secret Manager
# Usage: ./setup-gcp-secretmanager.sh <gcp-project-id>
#
# Prerequisites:
#   - gcloud CLI logged in (gcloud auth login)
#   - User has roles/secretmanager.admin on the project
#   - Compute Engine default service account or Workload Identity
#     will be granted roles/secretmanager.secretAccessor separately

PROJECT_ID="${1:?Usage: $0 <gcp-project-id>}"

echo "=== Storing PAM secrets in GCP Secret Manager (project: $PROJECT_ID) ==="

# Read from env vars (must be set)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
ENTRA_PIM_CLIENT_SECRET="${ENTRA_PIM_CLIENT_SECRET:-}"
ENTRA_PIM_CERTIFICATE_B64="${ENTRA_PIM_CERTIFICATE_B64:-}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_SSO_INSTANCE_ARN="${AWS_SSO_INSTANCE_ARN:-}"

create_or_update_secret() {
    local name="$1"
    local value="$2"

    if [ -z "$value" ]; then
        echo "  Skipping $name (empty)"
        return
    fi

    # Check if secret exists
    if gcloud secrets describe "$name" --project="$PROJECT_ID" >/dev/null 2>&1; then
        echo "  Updating existing secret: $name"
        echo -n "$value" | gcloud secrets versions add "$name" \
            --data-file=- \
            --project="$PROJECT_ID"
    else
        echo "  Creating new secret: $name"
        echo -n "$value" | gcloud secrets create "$name" \
            --data-file=- \
            --project="$PROJECT_ID" \
            --replication-policy="automatic"
    fi
}

echo "Storing secrets..."
create_or_update_secret "pam-django-secret-key" "$DJANGO_SECRET_KEY"
create_or_update_secret "pam-entra-client-secret" "$ENTRA_CLIENT_SECRET"
create_or_update_secret "pam-entra-pim-client-secret" "$ENTRA_PIM_CLIENT_SECRET"
create_or_update_secret "pam-entra-pim-cert" "$ENTRA_PIM_CERTIFICATE_B64"
create_or_update_secret "pam-aws-access-key" "$AWS_ACCESS_KEY_ID"
create_or_update_secret "pam-aws-secret-key" "$AWS_SECRET_ACCESS_KEY"
create_or_update_secret "pam-aws-sso-instance-arn" "$AWS_SSO_INSTANCE_ARN"

echo ""
echo "=== Done! ==="
echo "Secrets stored in GCP Secret Manager (project: $PROJECT_ID)"
echo ""
echo "Grant the app's service account access with:"
echo "  gcloud secrets add-iam-policy-binding pam-django-secret-key \\"
echo "    --member='serviceAccount:<app-sa>@${PROJECT_ID}.iam.gserviceaccount.com' \\"
echo "    --role='roles/secretmanager.secretAccessor' --project=$PROJECT_ID"
echo ""
echo "Then set GOOGLE_CLOUD_PROJECT env var on the app:"
echo "  GOOGLE_CLOUD_PROJECT=$PROJECT_ID"
