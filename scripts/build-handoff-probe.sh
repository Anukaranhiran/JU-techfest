#!/bin/bash
# Builds a stub "browser" app used ONLY by integration tests. It logs the exact URL that
# macOS hands it, proving where ScamShield sent the link.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/HandoffProbe/HandoffProbe.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

rm -rf "$ROOT/build/HandoffProbe"
mkdir -p "$OUT/Contents/MacOS"

cat > "$OUT/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>HandoffProbe</string>
<key>CFBundleIdentifier</key><string>com.scamshield.handoffprobe</string>
<key>CFBundleName</key><string>HandoffProbe</string>
<key>CFBundleDisplayName</key><string>Handoff Probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>CFBundleURLTypes</key><array><dict>
  <key>CFBundleURLName</key><string>Web URLs</string>
  <key>CFBundleTypeRole</key><string>Viewer</string>
  <key>CFBundleURLSchemes</key><array><string>http</string><string>https</string></array>
</dict></array>
</dict></plist>
PLIST

swiftc -O "$ROOT/tests/support/HandoffProbe.swift" -o "$OUT/Contents/MacOS/HandoffProbe"
codesign --force --sign - --identifier com.scamshield.handoffprobe "$OUT" >/dev/null 2>&1
"$LSREGISTER" -f "$OUT"
echo "$OUT"
