#!/usr/bin/env bash
# AWG Split Tunnel — One-line installer for macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Fokir/Ianus-Split-Tunnel-VPN/master/scripts/install-macos.sh | sudo bash
#   Options: --no-gui  Skip GUI application installation (daemon only)
#
# What this script does:
#   1. Detects your Mac's architecture (Apple Silicon / Intel)
#   2. Downloads the latest release tarball from GitHub
#   3. Extracts it to a temporary directory
#   4. Runs the install-daemon.sh script (installs binary + LaunchDaemon)
#   5. Downloads and installs the GUI application from DMG (unless --no-gui)
#   6. Cleans up the temporary files

set -euo pipefail

INSTALL_GUI=true
for arg in "$@"; do
    case "$arg" in
        --no-gui) INSTALL_GUI=false ;;
    esac
done

REPO="Fokir/Ianus-Split-Tunnel-VPN"

# ── Check prerequisites ──────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Error: This installer is for macOS only."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    echo "Usage: curl -fsSL <url> | sudo bash"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo "Error: curl is required."
    exit 1
fi

# ── Detect architecture ──────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
    arm64)  SUFFIX="darwin-arm64" ;;
    x86_64) SUFFIX="darwin-amd64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "AWG Split Tunnel — macOS Installer"
echo "  Architecture: $ARCH ($SUFFIX)"

# ── Fetch latest release tag ─────────────────────────────────────────
echo "  Fetching latest release..."
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')

if [[ -z "$LATEST_TAG" ]]; then
    echo "Error: Could not determine latest release."
    exit 1
fi

echo "  Latest version: $LATEST_TAG"

# ── Build download URL ───────────────────────────────────────────────
TARBALL="awg-split-tunnel-${LATEST_TAG}-${SUFFIX}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${TARBALL}"

# ── Download and extract ─────────────────────────────────────────────
TMPDIR_INSTALL="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR_INSTALL"; }
trap cleanup EXIT

echo "  Downloading ${TARBALL}..."
curl -fSL --progress-bar -o "${TMPDIR_INSTALL}/${TARBALL}" "$URL"

echo "  Extracting..."
tar xzf "${TMPDIR_INSTALL}/${TARBALL}" -C "$TMPDIR_INSTALL"

# ── Run install-daemon.sh ────────────────────────────────────────────
INSTALL_SCRIPT="${TMPDIR_INSTALL}/install-daemon.sh"
if [[ ! -f "$INSTALL_SCRIPT" ]]; then
    echo "Error: install-daemon.sh not found in the archive."
    exit 1
fi

chmod +x "$INSTALL_SCRIPT"
bash "$INSTALL_SCRIPT"

# ── Install GUI (DMG) ───────────────────────────────────────────────
if [[ "$INSTALL_GUI" == "true" ]]; then
    DMG_NAME="AWG-Split-Tunnel-${LATEST_TAG}-darwin-universal.dmg"
    DMG_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${DMG_NAME}"
    DMG_PATH="${TMPDIR_INSTALL}/${DMG_NAME}"
    MOUNT_POINT="${TMPDIR_INSTALL}/dmg-mount"

    echo "  Downloading GUI (${DMG_NAME})..."
    curl -fSL --progress-bar -o "$DMG_PATH" "$DMG_URL"

    echo "  Installing GUI to /Applications..."
    mkdir -p "$MOUNT_POINT"
    hdiutil attach "$DMG_PATH" -nobrowse -quiet -mountpoint "$MOUNT_POINT"

    APP_BUNDLE="$(find "$MOUNT_POINT" -maxdepth 1 -name '*.app' -print -quit)"
    if [[ -z "$APP_BUNDLE" ]]; then
        hdiutil detach "$MOUNT_POINT" -quiet
        echo "Warning: No .app bundle found in DMG, skipping GUI installation."
    else
        rm -rf "/Applications/$(basename "$APP_BUNDLE")"
        cp -R "$APP_BUNDLE" /Applications/
        xattr -cr "/Applications/$(basename "$APP_BUNDLE")"
        hdiutil detach "$MOUNT_POINT" -quiet
        echo "  GUI installed: /Applications/$(basename "$APP_BUNDLE")"
    fi
fi

echo ""
echo "Installation complete!"
if [[ "$INSTALL_GUI" == "true" ]]; then
    echo "  GUI: open /Applications/AWG\\ Split\\ Tunnel.app"
fi
echo "  Config: sudo nano /etc/awg-split-tunnel/config.yaml"
echo "  Restart daemon: sudo launchctl kickstart -k system/com.awg.split-tunnel"
