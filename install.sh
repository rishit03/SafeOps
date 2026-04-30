#!/usr/bin/env bash

set -e

echo "Installing SafeOps..."

# Clone repo
REPO_URL="https://github.com/rishit03/SafeOps.git"
INSTALL_DIR="$HOME/safeops"

if [ -d "$INSTALL_DIR" ]; then
    echo "SafeOps already exists at $INSTALL_DIR"
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install CLI
pip install -e .

echo ""
echo "SafeOps installed successfully!"
echo ""
echo "Try running:"
echo "  safeops scan"
echo ""