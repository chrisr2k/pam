#!/bin/bash
set -uo pipefail

# Store PAM secrets in OCI Vault
# Usage: ./setup-oci-vault.sh <vault-ocid> <compartment-ocid> [encryption-key-ocid] [--auth instance_principal]
#
# Prerequisites:
#   - OCI CLI installed and configured (or use --auth instance_principal on OCI instances)
#   - User/instance has manage secrets permission on the compartment
#
# Examples:
#   ./setup-oci-vault.sh ocid1.vault... ocid1.tenancy... ocid1.key...
#   ./setup-oci-vault.sh ocid1.vault... ocid1.tenancy... ocid1.key... --auth instance_principal

VAULT_OCID="${1:?Usage: $0 <vault-ocid> <compartment-ocid> [encryption-key-ocid] [--auth instance_principal]}"
COMPARTMENT_OCID="${2:?Usage: $0 <vault-ocid> <compartment-ocid> [encryption-key-ocid] [--auth instance_principal]}"
ENCRYPTION_KEY="${3:-}"
AUTH_FLAG=""

# Check for --auth flag (can be in position 4 or later)
for arg in "$@"; do
    if [ "$arg" = "--auth" ]; then
        AUTH_FLAG="--auth instance_principal"
    fi
done

echo "=== Storing PAM secrets in OCI Vault ==="
echo "Auth mode: ${AUTH_FLAG:-config file (user/API key)}"

# Read from env vars (must be set)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
ENTRA_PIM_CLIENT_SECRET="${ENTRA_PIM_CLIENT_SECRET:-}"
ENTRA_PIM_CERTIFICATE_B64="${ENTRA_PIM_CERTIFICATE_B64:-}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_SSO_INSTANCE_ARN="${AWS_SSO_INSTANCE_ARN:-}"

# If no encryption key provided, get the vault's default master key
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "  No encryption key provided, fetching vault's default master key..."
    MANAGEMENT_ENDPOINT=$(oci kms management vault get \
        $AUTH_FLAG \
        --vault-id "$VAULT_OCID" \
        --query 'data."management-endpoint"' \
        --raw-output 2>/dev/null) || {
        echo "  Could not fetch vault management endpoint."
        echo "  Please provide the key OCID as the third argument."
        echo "  You can find it in OCI Console > Vault > your vault > Master Encryption Key"
        exit 1
    }

    ENCRYPTION_KEY=$(oci kms management key list \
        $AUTH_FLAG \
        --compartment-id "$COMPARTMENT_OCID" \
        --endpoint "$MANAGEMENT_ENDPOINT" \
        --query 'data[0].id' \
        --raw-output 2>/dev/null) || {
        echo "  Could not auto-detect vault encryption key."
        echo "  Please provide the key OCID as the third argument."
        echo "  You can find it in OCI Console > Vault > your vault > Master Encryption Key"
        exit 1
    }
    echo "  Using vault master key: $ENCRYPTION_KEY"
fi

# Track created secret OCIDs
declare -A SECRET_OCIDS

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

    # Check if secret already exists
    local existing_ocid
    existing_ocid=$(oci vault secret list \
        $AUTH_FLAG \
        --compartment-id "$COMPARTMENT_OCID" \
        --name "$name" \
        --query 'data[0].id' \
        --raw-output 2>/dev/null || echo "")

    if [ -n "$existing_ocid" ] && [ "$existing_ocid" != "null" ]; then
        echo "  Secret $name already exists (OCID: $existing_ocid), updating..."
        oci vault secret update-base64 \
            $AUTH_FLAG \
            --secret-id "$existing_ocid" \
            --secret-content-content "$b64_value" \
            --secret-content-name "content" \
            --secret-content-stage "CURRENT" \
            --wait-for-state "ACTIVE" 2>&1 || echo "  Warning: update may have failed (secret might be in pending state)"
        echo "  Updated secret: $name"
        SECRET_OCIDS["$name"]="$existing_ocid"
    else
        echo "  Creating new secret: $name"
        local result
        result=$(oci vault secret create-base64 \
            $AUTH_FLAG \
            --vault-id "$VAULT_OCID" \
            --compartment-id "$COMPARTMENT_OCID" \
            --secret-name "$name" \
            --secret-content-content "$b64_value" \
            --secret-content-name "content" \
            --secret-content-stage "CURRENT" \
            --key-id "$ENCRYPTION_KEY" \
            --wait-for-state "ACTIVE" \
            2>&1) || {
            echo "  Failed to create secret $name: $result"
            return
        }

        local secret_ocid
        secret_ocid=$(echo "$result" | jq -r '.data.id' 2>/dev/null || echo "")
        if [ -n "$secret_ocid" ] && [ "$secret_ocid" != "null" ]; then
            echo "  Created secret: $name (OCID: $secret_ocid)"
            SECRET_OCIDS["$name"]="$secret_ocid"
        fi
    fi
}

echo "Storing secrets..."
create_or_update_secret "pam_django_secret_key" "$DJANGO_SECRET_KEY"
create_or_update_secret "pam_entra_client_secret" "$ENTRA_CLIENT_SECRET"
create_or_update_secret "pam_entra_pim_client_secret" "$ENTRA_PIM_CLIENT_SECRET"
create_or_update_secret "pam_entra_pim_cert" "$ENTRA_PIM_CERTIFICATE_B64"
create_or_update_secret "pam_entra_pim_cert_password" "$ENTRA_PIM_CERTIFICATE_PASSWORD"
create_or_update_secret "pam_aws_access_key_id" "$AWS_ACCESS_KEY_ID"
create_or_update_secret "pam_aws_secret_access_key" "$AWS_SECRET_ACCESS_KEY"
create_or_update_secret "pam_aws_sso_instance_arn" "$AWS_SSO_INSTANCE_ARN"

echo ""
echo "=== Done! ==="
echo "Secrets stored in OCI Vault"
echo ""

# Print the env vars needed for the app
if [ ${#SECRET_OCIDS[@]} -gt 0 ]; then
    echo "Add these environment variables to your app:"
    echo ""
    echo "# Required: tells the app to use OCI Vault"
    echo "OCI_VAULT_OCID=$VAULT_OCID"
    echo "# Required: set individual secret OCIDs so the app can fetch them:"
    for name in "${!SECRET_OCIDS[@]}"; do
        env_name="OCI_SECRET_OCID_$(echo "$name" | tr '[:lower:]' '[:upper:]')"
        echo "$env_name=${SECRET_OCIDS[$name]}"
    done
fi

echo ""
echo "Grant the app's instance principal access with a dynamic group policy:"
echo '  Allow dynamic-group <your-dg> to read secret-bundles in compartment <compartment-name>'
echo ""
echo "Then set OCI_VAULT_OCID and OCI_SECRET_OCID_* env vars on the app and restart."
