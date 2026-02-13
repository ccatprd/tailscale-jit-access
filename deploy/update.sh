#!/usr/bin/env bash
# =============================================================================
# Tailscale JIT Access Management - Update Script
# =============================================================================
# Pulls the latest code from git and copies it to /opt/tailscale-jit-access/,
# then restarts the service. Run from the repo root.
#
# Usage: sudo bash deploy/update.sh
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="/opt/tailscale-jit-access"
APP_USER="jitaccess"

echo "=== Tailscale JIT Access: Update ==="

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

if [[ ! -d "$APP_DIR" ]]; then
    echo "ERROR: $APP_DIR not found. Run deploy/setup.sh first."
    exit 1
fi

# Pull latest code
echo "Pulling latest code..."
git -C "$REPO_DIR" pull

# Copy updated files
echo "Copying files to $APP_DIR..."
cp "$REPO_DIR/app.py" "$APP_DIR/"
cp "$REPO_DIR/config.py" "$APP_DIR/"
cp "$REPO_DIR/requirements.txt" "$APP_DIR/"
cp "$REPO_DIR/gunicorn.conf.py" "$APP_DIR/"
cp -r "$REPO_DIR/templates" "$APP_DIR/"

# Install any new dependencies
echo "Updating dependencies..."
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# Fix ownership
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# Restart the service
echo "Restarting jit-access service..."
systemctl restart jit-access

echo ""
echo "=== Update complete ==="
echo ""
systemctl status jit-access --no-pager -l
