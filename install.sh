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
if safeops doctor; then
    echo ""
    echo "Setup check completed."
else
    echo ""
    echo "Warning: SafeOps installed, but setup check reported issues."
    echo "You can still continue, but review the output above before running cloud scans."
fi

echo ""
echo "Next steps:"
echo "1. Run your first cloud scan:"
echo "   safeops cloud scan"
echo ""
echo "2. Keep SafeOps monitoring for new risks:"
echo "   safeops start --cloud"
echo ""
echo "3. Optional Slack alerts:"
echo "   safeops config set slack_webhook_url <url>"
echo ""
echo "4. Quick status later:"
echo "   safeops cloud check"
echo ""