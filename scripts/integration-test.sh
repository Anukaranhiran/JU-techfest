#!/bin/bash
# End-to-end check of the interception pipeline using the real app bundle:
#   link delivery → scan → decision window → cancel / approve → browser handoff
# The stub browser records the URL it receives so "stayed closed" and "opened" are both
# verified from outside the app.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP="$ROOT/dist/ScamShield.app"
LOG="${HANDOFF_PROBE_LOG:-/tmp/scamshield-handoff.log}"

echo "==> building app"
"$ROOT/scripts/build-app.sh" >/dev/null || { echo "build failed"; exit 1; }

echo "==> building stub browser"
PROBE=$("$ROOT/scripts/build-handoff-probe.sh") || { echo "probe build failed"; exit 1; }

# Quit any previous instance of ScamShield only (exact path match, no broad pkill), then wait
# for it to really exit: the app refuses to run twice, so a survivor would make this test
# exit immediately and look like a crash.
PATTERN="$ROOT/dist/ScamShield.app/Contents/MacOS/ScamShield"
for pid in $(pgrep -f "$PATTERN" 2>/dev/null || true); do
  kill "$pid" 2>/dev/null || true
done
for _ in $(seq 1 25); do
  pgrep -f "$PATTERN" >/dev/null 2>&1 || break
  sleep 0.2
done
if pgrep -f "$PATTERN" >/dev/null 2>&1; then
  echo "a previous ScamShield instance is still running; stop it first (./scripts/stop.sh)" >&2
  exit 1
fi

rm -f "$LOG"
: > "$LOG"

echo "==> running in-app integration test"
HANDOFF_PROBE_LOG="$LOG" \
SCAMSHIELD_TEST_BROWSER_BUNDLE_ID="com.scamshield.handoffprobe" \
"$APP/Contents/MacOS/ScamShield" --integration-test
STATUS=$?

echo
echo "--- stub browser log ---"
cat "$LOG" 2>/dev/null || echo "(empty)"
echo "-------------------------"

# Keep the stub out of the user's browser list until the next test run.
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
"$LSREGISTER" -u "$PROBE" >/dev/null 2>&1 || true

# Registering and unregistering a browser app can make LaunchServices re-derive the default
# web handler, and this machine may then land on ScamShield. A test must not leave the user's
# links going to a checker they did not enable, so hand them back to the browser that was
# configured before the test (recorded by the app, or Opera GX when nothing was recorded).
HANDLER_NOW=$("$APP/Contents/MacOS/scamshieldctl" handler-status 2>/dev/null | awk -F'-> ' '/https ->/{print $2}' | tr -d ' ')
if [[ "$HANDLER_NOW" == "com.scamshield.app" ]]; then
  PREVIOUS_BROWSER=$(python3 -c "
import json, os
path = os.path.expanduser('~/Library/Application Support/ScamShield/settings.json')
try:
    value = json.load(open(path)).get('previousDefaultBundleID') or ''
except Exception:
    value = ''
print(value if value and value != 'com.scamshield.app' else 'com.operasoftware.OperaGX')
")
  echo "==> the test left ScamShield holding http/https; restoring $PREVIOUS_BROWSER"
  "$ROOT/scripts/restore-browser.sh" "$PREVIOUS_BROWSER" >/dev/null 2>&1 || true
  echo "    now: $("$APP/Contents/MacOS/scamshieldctl" handler-status 2>/dev/null | awk -F'-> ' '/https ->/{print $2}' | tr -d ' ')"
fi

exit $STATUS
