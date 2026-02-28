#!/usr/bin/env bash
set -euo pipefail

# ssroute installer — downloads and installs the latest release.
# Usage: curl -sSL https://github.com/<user>/ssroute/releases/latest/download/install.sh | sudo bash

REPO="pnv1/ssroute"  # TODO: update with actual GitHub user/org
INSTALL_DIR="/usr/bin"
CONFIG_DIR="/etc/ssroute"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="ssroute"

# --- Detect architecture ---
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    armv7l)  TARGET="armv7-unknown-linux-gnueabihf" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "==> Detected architecture: $ARCH ($TARGET)"

# --- Find latest release ---
LATEST_URL="https://api.github.com/repos/$REPO/releases/latest"
echo "==> Fetching latest release info..."
RELEASE_JSON="$(curl -sSL "$LATEST_URL")"
VERSION="$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest release version."
    echo "Check https://github.com/$REPO/releases"
    exit 1
fi

echo "==> Latest version: $VERSION"

# --- Download ---
TARBALL="ssroute-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$TARBALL"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Downloading $DOWNLOAD_URL ..."
curl -sSL -o "$TMPDIR/$TARBALL" "$DOWNLOAD_URL"

echo "==> Extracting..."
tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

# --- Check if service is running (for restart later) ---
WAS_RUNNING=false
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    WAS_RUNNING=true
    echo "==> Stopping $SERVICE_NAME service..."
    systemctl stop "$SERVICE_NAME"
fi

# --- Install binary ---
echo "==> Installing binary to $INSTALL_DIR/$SERVICE_NAME"
install -m 0755 "$TMPDIR/ssroute" "$INSTALL_DIR/$SERVICE_NAME"

# --- Install config and data ---
mkdir -p "$CONFIG_DIR"

if [ -d "$TMPDIR/data" ]; then
    echo "==> Updating route data in $CONFIG_DIR/data/"
    cp -r "$TMPDIR/data" "$CONFIG_DIR/"
fi

if [ -d "$TMPDIR/default_route" ]; then
    echo "==> Updating default routes in $CONFIG_DIR/default_route/"
    cp -r "$TMPDIR/default_route" "$CONFIG_DIR/"
fi

# Config: only create if missing (never overwrite user config)
if [ ! -f "$CONFIG_DIR/ssroute.conf" ]; then
    if [ -f "$TMPDIR/ssroute.conf.example" ]; then
        echo "==> Creating initial config at $CONFIG_DIR/ssroute.conf"
        cp "$TMPDIR/ssroute.conf.example" "$CONFIG_DIR/ssroute.conf"
        echo "    ** Edit $CONFIG_DIR/ssroute.conf before starting the service **"
    fi
else
    echo "==> Config $CONFIG_DIR/ssroute.conf already exists, not overwriting"
fi

# --- Install systemd service ---
if [ -f "$TMPDIR/ssroute.service" ]; then
    cp "$TMPDIR/ssroute.service" "$SYSTEMD_DIR/$SERVICE_NAME.service"
elif [ -f "$(dirname "$0")/ssroute.service" ]; then
    cp "$(dirname "$0")/ssroute.service" "$SYSTEMD_DIR/$SERVICE_NAME.service"
fi
systemctl daemon-reload

# --- Restart if was running ---
if [ "$WAS_RUNNING" = true ]; then
    echo "==> Restarting $SERVICE_NAME service..."
    systemctl start "$SERVICE_NAME"
fi

echo ""
echo "==> ssroute $VERSION installed successfully!"
echo ""
echo "Files:"
echo "  Binary:  $INSTALL_DIR/$SERVICE_NAME"
echo "  Config:  $CONFIG_DIR/ssroute.conf"
echo "  Routes:  $CONFIG_DIR/data/, $CONFIG_DIR/default_route/"
echo "  Service: $SYSTEMD_DIR/$SERVICE_NAME.service"
echo ""
if [ "$WAS_RUNNING" = true ]; then
    echo "Service was restarted."
else
    echo "To start:  sudo systemctl enable --now $SERVICE_NAME"
fi
