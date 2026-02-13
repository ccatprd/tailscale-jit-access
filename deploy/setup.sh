#!/usr/bin/env bash
# =============================================================================
# Tailscale JIT Access Management: Quick Setup Script
# =============================================================================
# Usage: sudo bash deploy/setup.sh
# =============================================================================
set -euo pipefail

# Resolve paths relative to the repository root (parent of deploy/)
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="/opt/tailscale-jit-access"
APP_USER="jitaccess"

echo "=== Tailscale JIT Access: Setup ==="
echo "Installing from: $REPO_DIR"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Check Tailscale
if ! command -v tailscale &> /dev/null; then
    echo "ERROR: Tailscale is not installed. Install it first:"
    echo "  curl -fsSL https://tailscale.com/install.sh | sh"
    exit 1
fi

# Check Python (install if missing; also ensure python3-venv is present)
if ! command -v python3 &> /dev/null; then
    echo "Installing Python 3..."
    apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv
elif ! python3 -c "import venv" &> /dev/null; then
    echo "Installing python3-venv..."
    apt-get update -qq && apt-get install -y -qq python3-venv
fi

# Create application user
if ! id "$APP_USER" &>/dev/null; then
    echo "Creating user: $APP_USER"
    useradd --system --home-dir "$APP_DIR" --shell /sbin/nologin "$APP_USER"
fi

# Create application directory
echo "Setting up $APP_DIR..."
mkdir -p "$APP_DIR"
cp "$REPO_DIR/app.py" "$APP_DIR/"
cp "$REPO_DIR/config.py" "$APP_DIR/"
cp "$REPO_DIR/requirements.txt" "$APP_DIR/"
cp "$REPO_DIR/gunicorn.conf.py" "$APP_DIR/"
cp -r "$REPO_DIR/templates" "$APP_DIR/"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# Set up .env if it doesn't exist
if [[ ! -f "$APP_DIR/.env" ]]; then
    echo ""
    echo "Creating .env from template..."
    cp "$REPO_DIR/.env.example" "$APP_DIR/.env"
    # Generate a random Flask secret key
    FLASK_KEY=$("$APP_DIR/venv/bin/python3" -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/^FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=$FLASK_KEY/" "$APP_DIR/.env"
    echo ""
    echo "!!  IMPORTANT: Edit $APP_DIR/.env with your Tailscale credentials  !!"
    echo ""
fi

# Set permissions
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 600 "$APP_DIR/.env"

# Install systemd services
echo "Installing systemd services..."
cp "$REPO_DIR/deploy/jit-access.service" /etc/systemd/system/
cp "$REPO_DIR/deploy/tailscale-serve.service" /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit $APP_DIR/.env with your Tailscale OAuth credentials"
echo "  2. Edit /etc/systemd/system/tailscale-serve.service with your capability domain"
echo "  3. Tag this device: sudo tailscale set --advertise-tags=tag:jit-access-app"
echo "  4. Start the services:"
echo "       sudo systemctl enable --now jit-access"
echo "       sudo systemctl enable --now tailscale-serve"
echo "  5. Check status: sudo systemctl status jit-access"
echo ""
