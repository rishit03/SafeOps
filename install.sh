#!/usr/bin/env bash

set -e

echo "Installing SafeOps..."

REPO_URL="https://github.com/rishit03/SafeOps.git"
INSTALL_DIR="$HOME/safeops"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "SafeOps already exists at $INSTALL_DIR"
    echo "Updating SafeOps..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

python3 -m venv venv
. venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

hash -r 2>/dev/null || true

echo ""
echo "Verifying SafeOps installation..."

if ! command -v safeops >/dev/null 2>&1; then
    echo "Error: SafeOps CLI was not installed correctly."
    exit 1
fi

echo ""
echo "SafeOps installed successfully."
echo ""

echo "Running setup check..."
safeops doctor 2>/dev/null || echo "Setup check not available yet."

echo ""
echo "Next steps:"
echo "1. Run: safeops cloud scan"
echo "2. Run: safeops start --cloud"
echo "3. Optional: safeops config set slack_webhook_url <url>"
echo ""
echo "If you want a quick status later, run:"
echo "  safeops cloud check"
echo ""