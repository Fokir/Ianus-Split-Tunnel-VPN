#!/usr/bin/env bash
# AWG Split Tunnel — Install LaunchDaemon on macOS
# Must be run as root (sudo).
# Usage: sudo ./scripts/install-daemon.sh [BINARY_PATH]

set -euo pipefail

LABEL="com.awg.split-tunnel"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="awg-split-tunnel"
PLIST_DIR="/Library/LaunchDaemons"
PLIST_FILE="${PLIST_DIR}/${LABEL}.plist"
CONFIG_DIR="/etc/awg-split-tunnel"
LOG_FILE="/var/log/awg-split-tunnel.log"

# ── Check root ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)."
    exit 1
fi

# ── Resolve source binary ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_BINARY="${1:-}"
if [[ -z "$SOURCE_BINARY" ]]; then
    # Look next to script (release tarball layout), then in build dir (dev layout).
    if [[ -f "${SCRIPT_DIR}/${BINARY_NAME}" ]]; then
        SOURCE_BINARY="${SCRIPT_DIR}/${BINARY_NAME}"
    else
        SOURCE_BINARY="${SCRIPT_DIR}/../build/${BINARY_NAME}"
    fi
fi

if [[ ! -f "$SOURCE_BINARY" ]]; then
    echo "Error: Binary not found: $SOURCE_BINARY"
    echo "Usage: sudo $0 [path/to/binary]"
    exit 1
fi

echo "Installing AWG Split Tunnel daemon..."

# ── Stop existing daemon (if running) ─────────────────────────────────
if launchctl print "system/${LABEL}" &>/dev/null; then
    echo "  Stopping existing daemon..."
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
fi

# ── Copy binary ──────────────────────────────────────────────────────
echo "  Copying binary to ${INSTALL_DIR}/${BINARY_NAME}..."
cp "$SOURCE_BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
xattr -cr "${INSTALL_DIR}/${BINARY_NAME}"

# ── Create config directory ──────────────────────────────────────────
mkdir -p "$CONFIG_DIR"

# Copy example config if config doesn't exist yet.
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    # Check next to script (tarball), then project root (dev).
    if [[ -f "${SCRIPT_DIR}/config.example.yaml" ]]; then
        EXAMPLE_CONFIG="${SCRIPT_DIR}/config.example.yaml"
    else
        EXAMPLE_CONFIG="${SCRIPT_DIR}/../config.example.yaml"
    fi
    if [[ -f "$EXAMPLE_CONFIG" ]]; then
        echo "  Copying example config to ${CONFIG_DIR}/config.yaml..."
        cp "$EXAMPLE_CONFIG" "${CONFIG_DIR}/config.yaml"
    fi
fi

# ── Write LaunchDaemon plist ──────────────────────────────────────────
echo "  Writing plist to ${PLIST_FILE}..."
cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${INSTALL_DIR}/${BINARY_NAME}</string>
		<string>-config</string>
		<string>${CONFIG_DIR}/config.yaml</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>${LOG_FILE}</string>
	<key>StandardErrorPath</key>
	<string>${LOG_FILE}</string>
</dict>
</plist>
EOF

# ── Bootstrap daemon ──────────────────────────────────────────────────
echo "  Starting daemon..."
launchctl bootstrap system "$PLIST_FILE"

echo ""
echo "Done! AWG Split Tunnel daemon is installed and running."
echo "  Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
echo "  Config:  ${CONFIG_DIR}/config.yaml"
echo "  Plist:   ${PLIST_FILE}"
echo "  Log:     ${LOG_FILE}"
echo ""
echo "Commands:"
echo "  sudo launchctl kickstart -k system/${LABEL}  # restart"
echo "  sudo launchctl print system/${LABEL}          # status"
echo "  tail -f ${LOG_FILE}                           # logs"
