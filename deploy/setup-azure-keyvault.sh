#!/bin/bash
set -euo pipefail

# Store PAM secrets in Azure Key Vault
# Usage: ./setup-azure-keyvault.sh <key-vault-name>
#
# Prerequisites:
#   - Azure CLI logged in (az login)
#   - User has Key Vault Secrets Officer role
#   - Managed Identity will be granted access separately

VAULT_NAME="${1:?Usage: $0 <key-vault-name>}"

echo "=== Storing PAM secrets in Azure Key Vault: $VAULT_NAME ==="

# Read from env vars (must be set)
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:?Must set DJANGO_SECRET_KEY}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?Must set ENTRA_CLIENT_SECRET}"
ENTRA_PIM_CLIENT_SECRET="${ENTRA_PIM_CLIENT_SECRET:-}"
ENTRA_PIM_CERTIFICATE_B64="${ENTRA_PIM_CERTIFICATE_B64:-}"
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

    echo "  Storing secret: $name"
    az keyvault secret set \
        --vault-name "$VAULT_NAME" \
        --name "$name" \
        --value "$value" \
        --output none
}

echo "Storing secrets..."
store_secret "pam-django-secret-key" "$DJANGO_SECRET_KEY"
store_secret "pam-entra-client-secret" "$ENTRA_CLIENT_SECRET"
store_secret "pam-entra-pim-client-secret" "$ENTRA_PIM_CLIENT_SECRET"
store_secret "pam-entra-pim-cert" "$ENTRA_PIM_CERTIFICATE_B64"
store_secret "pam-aws-access-key" "$AWS_ACCESS_KEY_ID"
store_secret "pam-aws-secret-key" "$AWS_SECRET_ACCESS_KEY"
store_secret "pam-aws-sso-instance-arn" "$AWS_SSO_INSTANCE_ARN"

echo ""
echo "=== Done! ==="
echo "Secrets stored in Azure Key Vault: $VAULT_NAME"
echo ""
echo "Grant the app's Managed Identity access with:"
echo "  az keyvault set-policy --name $VAULT_NAME \\"
echo "    --object-id <managed-identity-object-id> \\"
echo "    --secret-permissions get list"
echo ""
echo "Then set AZURE_KEY_VAULT_URL env var on the app:"
echo "  AZURE_KEY_VAULT_URL=https://${VAULT_NAME}.vault.azure.net/"
