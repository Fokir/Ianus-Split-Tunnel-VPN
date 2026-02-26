#!/usr/bin/env bash
# AWG Split Tunnel — macOS build script
# Usage:
#   ./scripts/build-darwin.sh [VERSION]
#   ./scripts/build-darwin.sh 0.2.0
#
# Produces:
#   build/awg-split-tunnel-arm64           (Apple Silicon)
#   build/awg-split-tunnel-amd64           (Intel)
#   build/awg-split-tunnel                 (Universal binary, if lipo available)
#   build/awg-split-tunnel-vVERSION-darwin-arm64.tar.gz
#   build/awg-split-tunnel-vVERSION-darwin-amd64.tar.gz

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Navigate to project root ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Arguments ─────────────────────────────────────────────────────────
VERSION="${1:-dev}"
if [[ "$VERSION" == "dev" ]]; then
    VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
fi
# Strip leading 'v' for ldflags.
VERSION_BARE="${VERSION#v}"

BINARY="awg-split-tunnel"
OUT_DIR="./build"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w -X main.version=${VERSION_BARE} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

mkdir -p "$OUT_DIR"

# ── Build arm64 ───────────────────────────────────────────────────────
info "Building arm64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
    go build -ldflags "$LDFLAGS" \
    -o "${OUT_DIR}/${BINARY}-arm64" ./cmd/awg-split-tunnel/
ok "arm64 binary: ${OUT_DIR}/${BINARY}-arm64"

# ── Build amd64 ───────────────────────────────────────────────────────
info "Building amd64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
    go build -ldflags "$LDFLAGS" \
    -o "${OUT_DIR}/${BINARY}-amd64" ./cmd/awg-split-tunnel/
ok "amd64 binary: ${OUT_DIR}/${BINARY}-amd64"

# ── Universal binary (optional, requires macOS with lipo) ────────────
if command -v lipo &>/dev/null; then
    info "Creating universal binary..."
    lipo -create -output "${OUT_DIR}/${BINARY}" \
        "${OUT_DIR}/${BINARY}-arm64" \
        "${OUT_DIR}/${BINARY}-amd64"
    ok "Universal binary: ${OUT_DIR}/${BINARY}"
fi

# ── Package tarballs ──────────────────────────────────────────────────
info "Creating release tarballs..."

# arm64 tarball
TAR_ARM64="${BINARY}-v${VERSION_BARE}-darwin-arm64.tar.gz"
tar -czf "${OUT_DIR}/${TAR_ARM64}" -C "${OUT_DIR}" "${BINARY}-arm64"
ok "arm64 tarball: ${OUT_DIR}/${TAR_ARM64}"

# amd64 tarball
TAR_AMD64="${BINARY}-v${VERSION_BARE}-darwin-amd64.tar.gz"
tar -czf "${OUT_DIR}/${TAR_AMD64}" -C "${OUT_DIR}" "${BINARY}-amd64"
ok "amd64 tarball: ${OUT_DIR}/${TAR_AMD64}"

# Universal tarball (if built)
if [[ -f "${OUT_DIR}/${BINARY}" ]]; then
    TAR_UNIVERSAL="${BINARY}-v${VERSION_BARE}-darwin-universal.tar.gz"
    tar -czf "${OUT_DIR}/${TAR_UNIVERSAL}" -C "${OUT_DIR}" "${BINARY}"
    ok "Universal tarball: ${OUT_DIR}/${TAR_UNIVERSAL}"
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Build complete!${NC}"
echo -e "  Version: ${GREEN}v${VERSION_BARE}${NC}"
echo -e "  Commit:  ${COMMIT}"
echo -e "  Output:  ${OUT_DIR}/"
