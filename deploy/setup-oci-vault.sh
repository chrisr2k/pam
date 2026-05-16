#!/bin/bash
set -euo pipefail

# Store PAM secrets in OCI Vault
# Usage: ./setup-oci-vault.sh <vault-ocid> <compartment-ocid>
#
# Prerequisites:
#   - OCI CLI installed and configured (or instance principal)
#   - User has manage secrets permission on the compartment
#   - Instance principal / OKE workload identity will be granted
#     access via dynamic group policies separately

VAULT_OCID="${1:?Usage: $0 <vault-ocid> <compartment-ocid>}"
COMPARTMENT_OCID="${2:?Usage: $0 <vault-ocid> <compartment-ocid>}"

echo "=== Storing PAM secrets in OCI Vault ==="

# Read from env vars (must be set)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
ENTRA_PIM_CLIENT_SECRET="${ENTRA_PIM_CLIENT_SECRET:-}"
ENTRA_PIM_CERTIFICATE_B64="${ENTRA_PIM_CERTIFICATE_B64:-}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_SSO_INSTANCE_ARN="${AWS_SSO_INSTANCE_ARN:-}"

# Generate a random 32-byte hex key for the vault encryption key
ENCRYPTION_KEY=$(openssl rand -hex 32)

create_or_update_secret() {
    local name="$1"
    local value="$2"

    if [ -z "$value" ]; then
        echo "  Skipping $name (empty)"
        return
    fi

    # Base64 encode the secret value
    local b64_value
    b64_value=$(echo -n "$value" | base64 -w0)

    echo "  Creating/updating secret: $name"

    # OCI CLI doesn't have a simple "upsert" for secrets, so we try create
    # and if it fails with conflict, we update
    oci vault secret create-base64 \
        --vault-id "$VAULT_OCID" \
        --compartment-id "$COMPARTMENT_OCID" \
        --secret-name "$name" \
        --secret-content-content "$b64_value" \
        --secret-content-name "content" \
        --secret-content-stage "CURRENT" \
        --key-id "$ENCRYPTION_KEY" \
        --wait-for-state "ACTIVE" \
        2>/dev/null || {
        echo "  Secret $name already exists, updating..."
        # Get the secret OCID by name
        local secret_ocid
        secret_ocid=$(oci vault secret list \
            --compartment-id "$COMPARTMENT_OCID" \
            --name "$name" \
            --query 'data[0].id' \
            --raw-output 2>/dev/null) || {
            echo "  Could not find existing secret $name, skipping update"
            return
        }
        if [ -n "$secret_ocid" ] && [ "$secret_ocid" != "null" ]; then
            oci vault secret update-base64 \
                --secret-id "$secret_ocid" \
                --secret-content-content "$b64_value" \
                --secret-content-name "content" \
                --secret-content-stage "CURRENT" \
                --wait-for-state "ACTIVE"
        fi
    }
}

echo "Storing secrets..."
create_or_update_secret "pam_django_secret_key" "$DJANGO_SECRET_KEY"
create_or_update_secret "pam_entra_client_secret" "$ENTRA_CLIENT_SECRET"
create_or_update_secret "pam_entra_pim_client_secret" "$ENTRA_PIM_CLIENT_SECRET"
create_or_update_secret "pam_entra_pim_cert" "$ENTRA_PIM_CERTIFICATE_B64"
create_or_update_secret "pam_aws_access_key_id" "$AWS_ACCESS_KEY_ID"
create_or_update_secret "pam_aws_secret_access_key" "$AWS_SECRET_ACCESS_KEY"
create_or_update_secret "pam_aws_sso_instance_arn" "$AWS_SSO_INSTANCE_ARN"

echo ""
echo "=== Done! ==="
echo "Secrets stored in OCI Vault"
echo ""
echo "Grant the app's instance principal access with a dynamic group policy:"
echo '  Allow dynamic-group <your-dg> to read secret-bundles in compartment <compartment-name>'
echo ""
echo "Then set OCI_VAULT_OCID env var on the app:"
echo "  OCI_VAULT_OCID=$VAULT_OCID"
