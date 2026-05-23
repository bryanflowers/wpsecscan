#!/usr/bin/env bash
# #74 — WPSecScan pre-commit hook
#
# Drop this file at .git/hooks/pre-commit (and chmod +x) to run a quick
# passive scan against your local dev WordPress before each commit. Aborts
# the commit if any new HIGH/CRITICAL finding appears versus the last
# scan stored as baseline.
#
# Configure the target:
#   git config wpsecscan.target "http://localhost:8000"
#
# Skip on a per-commit basis:
#   git commit --no-verify

set -e

TARGET=$(git config wpsecscan.target || true)
if [ -z "$TARGET" ]; then
    echo "[wpsecscan pre-commit] No target configured. Skipping. (Set: git config wpsecscan.target <url>)"
    exit 0
fi

BASELINE="$HOME/.wpsecscan/reports/pre-commit-baseline.json"

if ! command -v wpsecscan >/dev/null 2>&1; then
    echo "[wpsecscan pre-commit] wpsecscan not on PATH. Skipping."
    exit 0
fi

echo "[wpsecscan pre-commit] Scanning $TARGET..."

if [ ! -f "$BASELINE" ]; then
    wpsecscan "$TARGET" --json-only --out "$BASELINE" --quiet || true
    echo "[wpsecscan pre-commit] Baseline created at $BASELINE. Commit allowed."
    exit 0
fi

TMPDIR=$(mktemp -d)
CURRENT="$TMPDIR/current.json"
wpsecscan "$TARGET" --json-only --out "$CURRENT" --quiet --no-live --diff-against "$BASELINE" > "$TMPDIR/diff.txt" 2>&1 || true

NEW_HIGH=$(grep -cE "^\s*\+ \[(HIGH|CRITICAL)\]" "$TMPDIR/diff.txt" || true)

if [ "$NEW_HIGH" -gt 0 ]; then
    echo "[wpsecscan pre-commit] BLOCKED — $NEW_HIGH new HIGH/CRITICAL finding(s) since the last scan:"
    grep -E "^\s*\+ \[(HIGH|CRITICAL)\]" "$TMPDIR/diff.txt"
    echo
    echo "Bypass with: git commit --no-verify"
    echo "Update baseline with: wpsecscan $TARGET --json-only --out $BASELINE"
    exit 1
fi

echo "[wpsecscan pre-commit] No new HIGH/CRITICAL findings. Commit allowed."
exit 0
