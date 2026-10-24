#!/bin/bash
# Recovery tool: hands the macOS http/https handler back to a real browser.
#
# Why this exists: on current macOS a program cannot point the default-browser setting at
# *another* app — only the app itself may claim the role, or the user picks it in System
# Settings. So if ScamShield is the handler and the user wants out, either the user picks a
# browser in System Settings, or this script rewrites the LaunchServices handler records.
#
# Usage: ./scripts/restore-browser.sh [bundle-id]   (default: com.operasoftware.OperaGX)
set -uo pipefail

TARGET="${1:-com.operasoftware.OperaGX}"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

echo "==> restoring web handler to $TARGET"

# Ensure the target is a registered http handler before pointing at it.
if ! /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" \
      "$(mdfind "kMDItemCFBundleIdentifier == '$TARGET'" | head -1)/Contents/Info.plist" >/dev/null 2>&1; then
  echo "warning: could not locate $TARGET via Spotlight; continuing anyway" >&2
fi

python3 - "$TARGET" <<'PY'
import plistlib, subprocess, sys

target = sys.argv[1]
domain = "com.apple.LaunchServices/com.apple.launchservices.secure"

raw = subprocess.run(["defaults", "export", domain, "-"], capture_output=True).stdout
data = plistlib.loads(raw) if raw else {}
handlers = data.get("LSHandlers", [])

schemes = {"http", "https"}
handlers = [h for h in handlers
            if h.get("LSHandlerURLScheme") not in schemes
            and h.get("LSHandlerContentType") != "com.apple.default-app.web-browser"]

for scheme in ("http", "https"):
    handlers.insert(0, {"LSHandlerURLScheme": scheme, "LSHandlerRoleAll": target})
handlers.insert(0, {"LSHandlerContentType": "com.apple.default-app.web-browser",
                    "LSHandlerRoleAll": target})

data["LSHandlers"] = handlers
with open("/tmp/scamshield-lshandlers.plist", "wb") as handle:
    handle.write(plistlib.dumps(data))
print("wrote /tmp/scamshield-lshandlers.plist")
PY

defaults import com.apple.LaunchServices/com.apple.launchservices.secure /tmp/scamshield-lshandlers.plist

# LaunchServices caches handler choices per user session; restarting its agent re-reads them.
killall lsd 2>/dev/null || true
sleep 1

CURRENT=$(python3 - <<'PY'
import plistlib, subprocess
raw = subprocess.run(["defaults", "export", "com.apple.LaunchServices/com.apple.launchservices.secure", "-"],
                     capture_output=True).stdout
d = plistlib.loads(raw) if raw else {}
for h in d.get("LSHandlers", []):
    if h.get("LSHandlerURLScheme") == "https":
        print(h.get("LSHandlerRoleAll", "?"))
        break
PY
)
echo "https handler is now: $CURRENT"
if [[ "$CURRENT" == "$TARGET" ]]; then
  echo "restored."
  exit 0
fi
echo "preference written but LaunchServices still reports '$CURRENT'." >&2
echo "Set it manually: System Settings › Desktop & Dock › Default web browser." >&2
exit 1
