#!/usr/bin/env bash
# AWG Split Tunnel — Uninstall LaunchDaemon on macOS
# Must be run as root (sudo).
# Usage: sudo ./scripts/uninstall-daemon.sh

set -euo pipefail

LABEL="com.awg.split-tunnel"
BINARY="${1:-/usr/local/bin/awg-split-tunnel}"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
CONFIG_DIR="/etc/awg-split-tunnel"
LOG_FILE="/var/log/awg-split-tunnel.log"
SOCK_FILE="/var/run/awg-split-tunnel.sock"

# ── Check root ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)."
    exit 1
fi

echo "Uninstalling AWG Split Tunnel daemon..."

# ── Stop and remove daemon ────────────────────────────────────────────
if launchctl print "system/${LABEL}" &>/dev/null; then
    echo "  Stopping daemon..."
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
fi

# ── Remove files ──────────────────────────────────────────────────────
echo "  Removing plist..."
rm -f "$PLIST"

echo "  Removing binary..."
rm -f "$BINARY"

echo "  Removing socket..."
rm -f "$SOCK_FILE"

echo "  Removing log file..."
rm -f "$LOG_FILE"

# ── Config directory (ask before removing) ────────────────────────────
if [[ -d "$CONFIG_DIR" ]]; then
    echo ""
    echo "Config directory exists: $CONFIG_DIR"
    echo -n "Remove it? [y/N]: "
    read -r CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo "  Config directory removed."
    else
        echo "  Config directory preserved."
    fi
fi

echo ""
echo "Done! AWG Split Tunnel daemon has been uninstalled."
