#!/bin/bash
# Removes ScamShield and, if it is the system web browser, restores a real browser first
# so links keep working. Data is kept unless --purge is passed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HOME/Applications/ScamShield.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

CURRENT_HTTPS=$(/usr/bin/defaults read com.apple.LaunchServices/com.apple.launchservices.secure LSHandlers 2>/dev/null | grep -A2 "LSHandlerURLScheme = https" | grep "LSHandlerRoleAll" | head -1 | sed 's/.*= *"\(.*\)";/\1/' | tr -d '"')
if [[ "$CURRENT_HTTPS" == "com.scamshield.app" ]]; then
  echo "==> ScamShield is the current web browser; restoring Safari first"
  if [[ -x "$DEST/Contents/MacOS/ScamShield" ]]; then
    "$DEST/Contents/MacOS/ScamShield" --restore-default com.apple.Safari || true
  elif [[ -x "$ROOT/dist/ScamShield.app/Contents/MacOS/ScamShield" ]]; then
    "$ROOT/dist/ScamShield.app/Contents/MacOS/ScamShield" --restore-default com.apple.Safari || true
  else
    echo "!! ScamShield is gone but still the handler. Set System Settings › Desktop & Dock › Default web browser."
  fi
fi

for pattern in "$DEST/Contents/MacOS/ScamShield" "$ROOT/dist/ScamShield.app/Contents/MacOS/ScamShield"; do
  for pid in $(pgrep -f "$pattern" 2>/dev/null || true); do
    echo "==> stopping $pid"
    kill "$pid" 2>/dev/null || true
  done
done
sleep 0.4

if [[ -d "$DEST" ]]; then
  "$LSREGISTER" -u "$DEST" 2>/dev/null || true
  rm -rf "$DEST"
  echo "==> removed $DEST"
fi
if [[ -d "$ROOT/dist/ScamShield.app" ]]; then
  "$LSREGISTER" -u "$ROOT/dist/ScamShield.app" 2>/dev/null || true
  rm -rf "$ROOT/dist/ScamShield.app"
  echo "==> removed build copy"
fi

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$HOME/Library/Application Support/ScamShield"
  echo "==> purged local history, settings and token"
else
  echo "Local history and settings kept at: ~/Library/Application Support/ScamShield"
  echo "Use ./scripts/uninstall.sh --purge to delete them."
fi
