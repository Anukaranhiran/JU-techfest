#!/bin/bash
# Installs ScamShield into ~/Applications (no admin rights) and launches it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HOME/Applications/ScamShield.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

"$ROOT/scripts/build-app.sh"

# Stop the build-tree copy before replacing the installed one.
"$ROOT/scripts/stop.sh" >/dev/null 2>&1 || true
pkill -f "$DEST/Contents/MacOS/ScamShield" 2>/dev/null || true
sleep 0.3

mkdir -p "$HOME/Applications"
rm -rf "$DEST"
cp -R "$ROOT/dist/ScamShield.app" "$DEST"
"$LSREGISTER" -f "$DEST"

echo "==> installed to $DEST"
open "$DEST"

echo
echo "If this is the first launch, macOS may ask you to confirm the app. It is ad-hoc"
echo "signed, not notarised: right-click → Open, or allow it under System Settings ›"
echo "Privacy & Security. Then enable protection from the ScamShield window."
