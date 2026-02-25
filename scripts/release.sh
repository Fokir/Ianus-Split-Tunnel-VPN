#!/usr/bin/env bash
# AWG Split Tunnel — One-command release pipeline
# Usage:
#   ./scripts/release.sh              # patch bump (0.1.6 → 0.1.7), interactive confirm
#   ./scripts/release.sh --minor      # minor bump (0.1.6 → 0.2.0)
#   ./scripts/release.sh --major      # major bump (0.1.6 → 1.0.0)
#   ./scripts/release.sh --version 0.3.0  # explicit version
#   ./scripts/release.sh --dry-run    # show what would happen, don't execute

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${BOLD}── $* ──${NC}"; }

# ── Navigate to project root ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Parse arguments ───────────────────────────────────────────────────
BUMP="patch"
EXPLICIT_VERSION=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --major)   BUMP="major"; shift ;;
        --minor)   BUMP="minor"; shift ;;
        --patch)   BUMP="patch"; shift ;;
        --version) EXPLICIT_VERSION="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--major|--minor|--patch] [--version X.Y.Z] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --major        Bump major version (0.1.6 → 1.0.0)"
            echo "  --minor        Bump minor version (0.1.6 → 0.2.0)"
            echo "  --patch        Bump patch version (0.1.6 → 0.1.7) [default]"
            echo "  --version X.Y.Z  Set explicit version"
            echo "  --dry-run      Show what would happen without executing"
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Step 1: Determine version ────────────────────────────────────────
step "Step 1: Determine version"

LAST_TAG=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo "")
if [[ -z "$LAST_TAG" ]]; then
    warn "No previous tags found, starting from v0.0.0"
    LAST_TAG="v0.0.0"
fi

# Strip leading 'v'
LAST_VER="${LAST_TAG#v}"

# Parse semver
IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "$LAST_VER"
V_MAJOR="${V_MAJOR:-0}"
V_MINOR="${V_MINOR:-0}"
V_PATCH="${V_PATCH:-0}"

info "Current version: ${BOLD}$LAST_TAG${NC}"

if [[ -n "$EXPLICIT_VERSION" ]]; then
    # Validate format
    if [[ ! "$EXPLICIT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        err "Invalid version format: $EXPLICIT_VERSION (expected X.Y.Z)"
        exit 1
    fi
    NEW_VER="$EXPLICIT_VERSION"
else
    case "$BUMP" in
        major) NEW_VER="$((V_MAJOR + 1)).0.0" ;;
        minor) NEW_VER="${V_MAJOR}.$((V_MINOR + 1)).0" ;;
        patch) NEW_VER="${V_MAJOR}.${V_MINOR}.$((V_PATCH + 1))" ;;
    esac
fi

NEW_TAG="v${NEW_VER}"

# Interactive confirmation (unless --dry-run or explicit version given)
if [[ "$DRY_RUN" == false && -z "$EXPLICIT_VERSION" ]]; then
    echo -e "Next version: ${BOLD}${GREEN}$NEW_TAG${NC} (${BUMP} bump)"
    echo -n "Press Enter to confirm, or type a new version (X.Y.Z): "
    read -r USER_INPUT
    if [[ -n "$USER_INPUT" ]]; then
        if [[ ! "$USER_INPUT" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            err "Invalid version format: $USER_INPUT"
            exit 1
        fi
        NEW_VER="$USER_INPUT"
        NEW_TAG="v${NEW_VER}"
    fi
fi

# Check tag doesn't already exist
if git rev-parse "$NEW_TAG" >/dev/null 2>&1; then
    err "Tag $NEW_TAG already exists!"
    exit 1
fi

ok "Release version: ${BOLD}$NEW_TAG${NC}"

# ── Dry-run summary ──────────────────────────────────────────────────
if [[ "$DRY_RUN" == true ]]; then
    step "Dry-run summary"
    echo -e "  Current tag:   ${CYAN}$LAST_TAG${NC}"
    echo -e "  New tag:       ${GREEN}$NEW_TAG${NC}"
    echo -e "  Bump type:     $BUMP"
    echo ""
    echo "  Steps that would execute:"
    echo "    1. Check prerequisites (go, npm, makensis, gh, git)"
    echo "    2. Run build.bat (frontend + Go binaries)"
    echo "    3. Build NSIS installer"
    echo "    4. Create release ZIP: awg-split-tunnel-${NEW_TAG}-windows-amd64.zip"
    echo "    5. Generate changelog from commits since $LAST_TAG"
    echo "    6. Create git tag $NEW_TAG and push"
    echo "    7. Create GitHub Release with artifacts"
    echo ""

    # Show commits that would be included
    COMMIT_COUNT=$(git log "${LAST_TAG}..HEAD" --oneline 2>/dev/null | wc -l)
    echo -e "  Commits since ${CYAN}$LAST_TAG${NC}: ${BOLD}$COMMIT_COUNT${NC}"
    if [[ "$COMMIT_COUNT" -gt 0 ]]; then
        echo ""
        git log "${LAST_TAG}..HEAD" --oneline
    fi
    echo ""
    info "Dry-run complete. No changes were made."
    exit 0
fi

# ── Step 2: Prerequisites ────────────────────────────────────────────
step "Step 2: Check prerequisites"

MISSING=()
for cmd in go npm makensis gh git; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING+=("$cmd")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Missing required tools: ${MISSING[*]}"
    echo "  Install them and ensure they are in PATH."
    exit 1
fi
ok "All tools found: go, npm, makensis, gh, git"

# Check gh auth
if ! gh auth status &>/dev/null; then
    err "GitHub CLI not authenticated. Run: gh auth login"
    exit 1
fi
ok "GitHub CLI authenticated"

# Check working tree
if [[ -n "$(git status --porcelain)" ]]; then
    warn "Working tree is dirty:"
    git status --short
    echo ""
    echo -n "Continue anyway? [y/N]: "
    read -r CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        info "Aborting."
        exit 1
    fi
else
    ok "Working tree is clean"
fi

# ── Step 3: Build ────────────────────────────────────────────────────
step "Step 3: Build all binaries"

APP_NAME="awg-split-tunnel"
OUT_DIR="./build"

# Clean up old release archives and installers
OLD_ZIPS=$(find "$OUT_DIR" -maxdepth 1 -name "${APP_NAME}-v*-windows-amd64.zip" -type f 2>/dev/null)
OLD_INSTALLERS=$(find "$OUT_DIR" -maxdepth 1 -name "*installer*.exe" -type f 2>/dev/null)
if [[ -n "$OLD_ZIPS" || -n "$OLD_INSTALLERS" ]]; then
    info "Cleaning up old release artifacts..."
    if [[ -n "$OLD_ZIPS" ]]; then
        echo "$OLD_ZIPS" | while read -r f; do
            rm -f "$f" && echo "  removed: $(basename "$f")"
        done
    fi
    if [[ -n "$OLD_INSTALLERS" ]]; then
        echo "$OLD_INSTALLERS" | while read -r f; do
            rm -f "$f" && echo "  removed: $(basename "$f")"
        done
    fi
    ok "Old artifacts cleaned"
fi

cmd //c build.bat
if [[ $? -ne 0 ]]; then
    err "build.bat failed"
    exit 1
fi

# Verify binaries exist
for bin in "$APP_NAME.exe" "$APP_NAME-ui.exe" "$APP_NAME-updater.exe"; do
    if [[ ! -f "$OUT_DIR/$bin" ]]; then
        err "Binary not found: $OUT_DIR/$bin"
        exit 1
    fi
done
ok "All binaries built successfully"

# ── Step 4: NSIS Installer ───────────────────────────────────────────
step "Step 4: Build NSIS installer"

NSIS_DIR="./ui/build/windows/nsis"

# Resolve absolute paths (Windows-style for NSIS)
ABS_SERVICE="$(cygpath -w "$(pwd)/$OUT_DIR/$APP_NAME.exe")"
ABS_GUI="$(cygpath -w "$(pwd)/$OUT_DIR/$APP_NAME-ui.exe")"
ABS_UPDATER="$(cygpath -w "$(pwd)/$OUT_DIR/$APP_NAME-updater.exe")"

# WinTUN DLL
if [[ -f "$OUT_DIR/wintun.dll" ]]; then
    ABS_WINTUN="$(cygpath -w "$(pwd)/$OUT_DIR/wintun.dll")"
elif [[ -f "dll/wintun.dll" ]]; then
    ABS_WINTUN="$(cygpath -w "$(pwd)/dll/wintun.dll")"
else
    ABS_WINTUN=""
fi

# Config example
ABS_CONFIG=""
if [[ -f "config.example.yaml" ]]; then
    ABS_CONFIG="$(cygpath -w "$(pwd)/config.example.yaml")"
fi

NSIS_ARGS=(
    -DARG_WAILS_AMD64_BINARY="$ABS_GUI"
    -DARG_SERVICE_BINARY="$ABS_SERVICE"
    -DARG_UPDATER_BINARY="$ABS_UPDATER"
    -DINFO_PRODUCTVERSION="$NEW_VER"
)

if [[ -n "$ABS_WINTUN" ]]; then
    NSIS_ARGS+=(-DARG_WINTUN_DLL="$ABS_WINTUN")
fi
if [[ -n "$ABS_CONFIG" ]]; then
    NSIS_ARGS+=(-DARG_CONFIG_EXAMPLE="$ABS_CONFIG")
fi

makensis "${NSIS_ARGS[@]}" "$NSIS_DIR/project.nsi"
if [[ $? -ne 0 ]]; then
    err "NSIS installer build failed"
    exit 1
fi
ok "Installer built"

# Find the installer file
INSTALLER=$(find "$OUT_DIR" -maxdepth 1 -name "*installer*.exe" -type f | head -1)
if [[ -n "$INSTALLER" ]]; then
    ok "Installer: $INSTALLER"
fi

# ── Step 5: Release ZIP ──────────────────────────────────────────────
step "Step 5: Create release ZIP"

ZIP_NAME="${APP_NAME}-${NEW_TAG}-windows-amd64.zip"
ZIP_PATH="$OUT_DIR/$ZIP_NAME"

# Remove old zip
rm -f "$ZIP_PATH"

# Collect files for zip
ZIP_FILES=(
    "$OUT_DIR/$APP_NAME.exe"
    "$OUT_DIR/$APP_NAME-ui.exe"
    "$OUT_DIR/$APP_NAME-updater.exe"
)
[[ -f "$OUT_DIR/wintun.dll" ]] && ZIP_FILES+=("$OUT_DIR/wintun.dll")
[[ -f "config.example.yaml" ]] && ZIP_FILES+=("config.example.yaml")

# Use PowerShell to create zip
POWERSHELL="$(cygpath -u "$SYSTEMROOT/System32/WindowsPowerShell/v1.0/powershell.exe")"
WIN_ZIP_PATH="$(cygpath -w "$ZIP_PATH")"
PS_FILES=""
for f in "${ZIP_FILES[@]}"; do
    WIN_F="$(cygpath -w "$f")"
    PS_FILES+="'$WIN_F',"
done
PS_FILES="${PS_FILES%,}" # trim trailing comma

"$POWERSHELL" -NoProfile -Command "Compress-Archive -Path $PS_FILES -DestinationPath '$WIN_ZIP_PATH' -Force"
if [[ $? -ne 0 ]]; then
    err "Failed to create release ZIP"
    exit 1
fi
ok "Release ZIP: $ZIP_PATH"

# ── Step 6: Generate changelog ───────────────────────────────────────
step "Step 6: Generate changelog"

CHANGELOG="$OUT_DIR/CHANGELOG.md"

{
    echo "# Changelog — $NEW_TAG"
    echo ""
    echo "Released: $(date +%Y-%m-%d)"
    echo ""

    # Collect commits grouped by conventional commit type
    declare -A GROUPS
    declare -a GROUP_ORDER=()

    while IFS= read -r line; do
        # Parse conventional commit: type(scope): message  OR  type: message
        if [[ "$line" =~ ^[a-f0-9]+\ ([a-zA-Z]+)(\(.*\))?:\ (.+)$ ]]; then
            TYPE="${BASH_REMATCH[1]}"
            MSG="${BASH_REMATCH[3]}"
            HASH="${line%% *}"
        else
            TYPE="other"
            MSG="${line#* }"
            HASH="${line%% *}"
        fi

        # Normalize type names
        case "$TYPE" in
            feat)     LABEL="Features" ;;
            fix)      LABEL="Bug Fixes" ;;
            refactor) LABEL="Refactoring" ;;
            perf)     LABEL="Performance" ;;
            docs)     LABEL="Documentation" ;;
            test)     LABEL="Tests" ;;
            ci)       LABEL="CI" ;;
            chore)    LABEL="Chores" ;;
            build)    LABEL="Build" ;;
            style)    LABEL="Style" ;;
            *)        LABEL="Other" ;;
        esac

        # Track group order (first occurrence)
        if [[ -z "${GROUPS[$LABEL]+x}" ]]; then
            GROUP_ORDER+=("$LABEL")
            GROUPS[$LABEL]=""
        fi
        GROUPS[$LABEL]+="- ${MSG} (\`${HASH}\`)"$'\n'
    done < <(git log "${LAST_TAG}..HEAD" --oneline --no-merges 2>/dev/null)

    # Print groups in order
    for label in "${GROUP_ORDER[@]}"; do
        echo "## $label"
        echo ""
        echo -n "${GROUPS[$label]}"
        echo ""
    done

    # If no commits found
    if [[ ${#GROUP_ORDER[@]} -eq 0 ]]; then
        echo "No changes since $LAST_TAG."
        echo ""
    fi

    echo "---"
    echo "Full diff: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo 'OWNER/REPO')/compare/${LAST_TAG}...${NEW_TAG}"
} > "$CHANGELOG"

ok "Changelog: $CHANGELOG"
echo ""
cat "$CHANGELOG"

# ── Step 7: Tag, push, publish ───────────────────────────────────────
step "Step 7: Create tag, push, and publish GitHub Release"

echo -e "About to:"
echo -e "  1. Create tag ${GREEN}$NEW_TAG${NC}"
echo -e "  2. Push to origin (master + tags)"
echo -e "  3. Create GitHub Release with artifacts"
echo ""
echo -n "Proceed? [Y/n]: "
read -r CONFIRM
if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    info "Aborting. Artifacts are in $OUT_DIR/"
    exit 0
fi

# Create annotated tag
git tag -a "$NEW_TAG" -m "Release $NEW_TAG"
ok "Tag created: $NEW_TAG"

# Push
git push origin master --tags
ok "Pushed to origin"

# Collect release assets
ASSETS=()
if [[ -n "$INSTALLER" && -f "$INSTALLER" ]]; then
    ASSETS+=("$INSTALLER")
fi
if [[ -f "$ZIP_PATH" ]]; then
    ASSETS+=("$ZIP_PATH")
fi
if [[ -f "$CHANGELOG" ]]; then
    ASSETS+=("$CHANGELOG")
fi

# Build gh release create command
GH_ARGS=(
    gh release create "$NEW_TAG"
    --title "Release $NEW_TAG"
    --notes-file "$CHANGELOG"
)
for asset in "${ASSETS[@]}"; do
    GH_ARGS+=("$asset")
done

"${GH_ARGS[@]}"
if [[ $? -ne 0 ]]; then
    err "GitHub Release creation failed"
    echo "  Tag $NEW_TAG was created and pushed. You can create the release manually:"
    echo "  gh release create $NEW_TAG ${ASSETS[*]}"
    exit 1
fi

ok "GitHub Release published: $NEW_TAG"

# ── Summary ──────────────────────────────────────────────────────────
step "Release complete!"
echo ""
echo -e "  Version:   ${GREEN}${BOLD}$NEW_TAG${NC}"
echo -e "  Tag:       $NEW_TAG"
if [[ -n "$INSTALLER" ]]; then
    echo -e "  Installer: $INSTALLER"
fi
echo -e "  ZIP:       $ZIP_PATH"
echo -e "  Changelog: $CHANGELOG"
echo ""
REPO_URL=$(gh repo view --json url -q .url 2>/dev/null || echo "")
if [[ -n "$REPO_URL" ]]; then
    echo -e "  ${CYAN}$REPO_URL/releases/tag/$NEW_TAG${NC}"
fi
echo ""
