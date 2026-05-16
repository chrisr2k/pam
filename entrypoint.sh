#!/bin/sh
# PAM Entrypoint Script
#
# Decrypts the .env file at container startup if an encrypted .env.enc exists.
# The master password is passed via ENV_MASTER_PASSWORD environment variable.
#
# Usage:
#   ENV_MASTER_PASSWORD=your-password docker compose up
#
# To encrypt your .env file:
#   ./encrypt-env.sh your-password

set -e

# If an encrypted .env.enc exists and ENV_MASTER_PASSWORD is set, decrypt it
if [ -f /app/.env.enc ] && [ -n "$ENV_MASTER_PASSWORD" ]; then
    echo "Decrypting .env.enc..."
    openssl enc -d -aes-256-cbc -salt -in /app/.env.enc -out /app/.env -pass pass:"$ENV_MASTER_PASSWORD" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to decrypt .env.enc. Check ENV_MASTER_PASSWORD."
        exit 1
    fi
    echo "Successfully decrypted .env.enc"
fi

# Execute the main command
exec "$@"
