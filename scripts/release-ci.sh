#!/usr/bin/env bash
# AWG Split Tunnel — Trigger CI/CD release via GitHub Actions
# Creates a git tag and pushes it; the Release workflow handles everything else.
#
# Usage:
#   ./scripts/release-ci.sh              # patch bump (0.1.6 → 0.1.7)
#   ./scripts/release-ci.sh --minor      # minor bump (0.1.6 → 0.2.0)
#   ./scripts/release-ci.sh --major      # major bump (0.1.6 → 1.0.0)
#   ./scripts/release-ci.sh --version 0.3.0  # explicit version
#   ./scripts/release-ci.sh --dry-run    # preview without executing
#   ./scripts/release-ci.sh --watch      # push tag and follow CI progress

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*" >&2; }

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Parse arguments ──────────────────────────────────────────────────
BUMP="patch"
EXPLICIT_VERSION=""
DRY_RUN=false
WATCH=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --major)   BUMP="major"; shift ;;
        --minor)   BUMP="minor"; shift ;;
        --patch)   BUMP="patch"; shift ;;
        --version) EXPLICIT_VERSION="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --watch)   WATCH=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--major|--minor|--patch] [--version X.Y.Z] [--dry-run] [--watch]"
            echo ""
            echo "Bumps version, creates a git tag, and pushes it to trigger"
            echo "the GitHub Actions Release workflow (builds Windows + macOS,"
            echo "creates GitHub Release with all artifacts)."
            echo ""
            echo "Options:"
            echo "  --major          Major bump  (0.1.6 → 1.0.0)"
            echo "  --minor          Minor bump  (0.1.6 → 0.2.0)"
            echo "  --patch          Patch bump  (0.1.6 → 0.1.7)  [default]"
            echo "  --version X.Y.Z  Explicit version"
            echo "  --dry-run        Preview what would happen"
            echo "  --watch          Follow CI progress after push"
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────
for cmd in git gh; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Required tool not found: $cmd"
        exit 1
    fi
done

if ! gh auth status &>/dev/null 2>&1; then
    err "GitHub CLI not authenticated. Run: gh auth login"
    exit 1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "master" && "$BRANCH" != "main" ]]; then
    warn "You are on branch '${BRANCH}', not master/main"
    echo -n "  Continue anyway? [y/N]: "
    read -r CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborting."; exit 0; }
fi

# Check for unpushed commits
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH" 2>/dev/null || echo "")
if [[ "$LOCAL" != "$REMOTE" ]]; then
    AHEAD=$(git rev-list "origin/$BRANCH..HEAD" --count 2>/dev/null || echo "?")
    warn "Branch has $AHEAD unpushed commit(s)"
    echo -n "  Push them first? [Y/n]: "
    read -r CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Nn]$ ]]; then
        git push origin "$BRANCH"
        ok "Pushed to origin/$BRANCH"
    fi
fi

# ── Determine version ───────────────────────────────────────────────
LAST_TAG=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo "")
if [[ -z "$LAST_TAG" ]]; then
    LAST_TAG="v0.0.0"
    warn "No previous tags found, starting from $LAST_TAG"
fi

LAST_VER="${LAST_TAG#v}"
IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "${LAST_VER%%-*}"
V_MAJOR="${V_MAJOR:-0}"; V_MINOR="${V_MINOR:-0}"; V_PATCH="${V_PATCH:-0}"

if [[ -n "$EXPLICIT_VERSION" ]]; then
    if [[ ! "$EXPLICIT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        err "Invalid version: $EXPLICIT_VERSION (expected X.Y.Z or X.Y.Z-suffix)"
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

if git rev-parse "$NEW_TAG" &>/dev/null; then
    err "Tag $NEW_TAG already exists!"
    exit 1
fi

# ── Preview ──────────────────────────────────────────────────────────
echo ""
info "Current: ${BOLD}$LAST_TAG${NC}"
echo -e "    New: ${BOLD}${GREEN}$NEW_TAG${NC}  (${BUMP} bump)"
echo ""

COMMIT_COUNT=$(git rev-list "${LAST_TAG}..HEAD" --count 2>/dev/null || echo "0")
info "Commits since $LAST_TAG: ${BOLD}$COMMIT_COUNT${NC}"
if [[ "$COMMIT_COUNT" -gt 0 ]]; then
    echo ""
    git log "${LAST_TAG}..HEAD" --oneline --no-merges | head -20
    [[ "$COMMIT_COUNT" -gt 20 ]] && echo "  ... and $((COMMIT_COUNT - 20)) more"
fi
echo ""

if [[ "$DRY_RUN" == true ]]; then
    info "Dry run — no changes made."
    echo ""
    echo "  Would execute:"
    echo "    git tag $NEW_TAG"
    echo "    git push origin $NEW_TAG"
    echo ""
    echo "  This triggers the Release workflow which builds:"
    echo "    • Windows: GUI + service + updater + NSIS installer + ZIP"
    echo "    • macOS:   daemon (arm64 + amd64 + universal) tarballs"
    echo "    • GitHub Release with auto-generated changelog"
    exit 0
fi

# ── Confirm & execute ────────────────────────────────────────────────
echo -n "Create tag ${GREEN}$NEW_TAG${NC} and push? [Y/n]: "
read -r CONFIRM
if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    info "Aborting."
    exit 0
fi

git tag -a "$NEW_TAG" -m "Release $NEW_TAG"
ok "Tag created: $NEW_TAG"

git push origin "$NEW_TAG"
ok "Tag pushed — Release workflow triggered"

# ── Watch CI (optional) ─────────────────────────────────────────────
echo ""
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
if [[ -n "$REPO" ]]; then
    echo -e "  ${CYAN}https://github.com/$REPO/actions${NC}"
fi

if [[ "$WATCH" == true ]]; then
    echo ""
    info "Waiting for Release workflow to start..."
    sleep 5

    RUN_ID=""
    for i in {1..10}; do
        RUN_ID=$(gh run list --workflow=release.yml --limit 1 --json databaseId,headBranch -q \
            ".[] | select(.headBranch == \"$NEW_TAG\" or .headBranch == \"refs/tags/$NEW_TAG\") | .databaseId" 2>/dev/null || echo "")
        # Fallback: grab the latest release run
        [[ -z "$RUN_ID" ]] && RUN_ID=$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || echo "")
        [[ -n "$RUN_ID" ]] && break
        sleep 3
    done

    if [[ -z "$RUN_ID" ]]; then
        warn "Could not find Release workflow run. Check GitHub Actions manually."
        exit 1
    fi

    ok "Watching run $RUN_ID..."
    echo ""
    gh run watch "$RUN_ID" --exit-status && STATUS=0 || STATUS=$?

    echo ""
    if [[ "$STATUS" -eq 0 ]]; then
        ok "${GREEN}${BOLD}Release $NEW_TAG published successfully!${NC}"
        [[ -n "$REPO" ]] && echo -e "  ${CYAN}https://github.com/$REPO/releases/tag/$NEW_TAG${NC}"
    else
        err "Release workflow failed!"
        echo "  Check: https://github.com/$REPO/actions/runs/$RUN_ID"
        exit 1
    fi
else
    echo ""
    ok "Done! The Release workflow will build and publish ${BOLD}$NEW_TAG${NC}"
    echo "  Run with --watch to follow CI progress, or check GitHub Actions."
fi
echo ""
