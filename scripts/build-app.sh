#!/bin/bash
# Builds ScamShield.app from source, ad-hoc signs it and registers it with LaunchServices.
# No admin rights, no network, no third-party dependencies.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-release}"
APP="$ROOT/dist/ScamShield.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

echo "==> swift build -c $CONFIG"
swift build -c "$CONFIG"

BIN="$ROOT/.build/$CONFIG/ScamShield"
CTL="$ROOT/.build/$CONFIG/scamshieldctl"
if [[ ! -x "$BIN" ]]; then
  echo "build failed: $BIN missing" >&2
  exit 1
fi

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/ScamShield"
cp "$CTL" "$APP/Contents/MacOS/scamshieldctl"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/THIRD-PARTY-NOTICES.md" "$APP/Contents/Resources/THIRD-PARTY-NOTICES.md"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# Extensions ship inside the bundle so the app can point users at them.
if [[ -d "$ROOT/extensions" ]]; then
  cp -R "$ROOT/extensions" "$APP/Contents/Resources/extensions"
fi

# Icon (optional; failures are not fatal)
if command -v iconutil >/dev/null 2>&1; then
  ICONSET="$ROOT/build/AppIcon.iconset"
  rm -rf "$ICONSET"
  if swift "$ROOT/scripts/make-icon.swift" "$ICONSET" >/dev/null 2>&1 \
     && iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
    echo "    icon embedded"
  else
    echo "    icon skipped (render failed)"
  fi
fi

echo "==> ad-hoc code signature"
codesign --force --sign - --identifier com.scamshield.app --timestamp=none "$APP"
codesign --verify --deep --strict "$APP" && echo "    signature verifies"

echo "==> registering with LaunchServices"
"$LSREGISTER" -f "$APP"

cat <<EOF

Built: $APP

Next:
  ./scripts/run.sh            launch (opens the dashboard)
  ./scripts/install.sh       copy to ~/Applications and launch
  ./scripts/stop.sh          quit any running instance
EOF
