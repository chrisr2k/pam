#!/bin/sh
# Encrypt the .env file for secure storage
#
# Usage:
#   ./encrypt-env.sh your-master-password
#
# This creates .env.enc from .env. You can safely commit .env.enc to git
# (it's already in .gitignore but you can remove it if you want).
# The .env file itself remains in .gitignore.
#
# To decrypt at runtime, set ENV_MASTER_PASSWORD and the entrypoint
# will automatically decrypt .env.enc before starting the app.

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <master-password>"
    exit 1
fi

PASSWORD="$1"

if [ ! -f .env ]; then
    echo "ERROR: .env file not found in current directory."
    echo "Create one from .env.example first:"
    echo "  cp .env.example .env"
    exit 1
fi

echo "Encrypting .env -> .env.enc..."
openssl enc -aes-256-cbc -salt -in .env -out .env.enc -pass pass:"$PASSWORD"

if [ $? -eq 0 ]; then
    echo "Success! Created .env.enc"
    echo ""
    echo "You can now safely delete .env:"
    echo "  rm .env"
    echo ""
    echo "To run the app:"
    echo "  ENV_MASTER_PASSWORD=$PASSWORD docker compose up -d"
    echo ""
    echo "WARNING: Keep this password safe! Without it, you cannot decrypt .env.enc."
else
    echo "ERROR: Encryption failed."
    exit 1
fi
