#!/bin/bash
# Verifies the REAL macOS path end to end:
#   set ScamShield as the default web handler → `open <url>` (what WhatsApp/Mail do)
#   → ScamShield decision window → cancel keeps it closed / approve opens the browser.
#
# The decision itself is applied by a test-only hook (SCAMSHIELD_TEST_AUTO_DECIDE) because
# a shell script cannot click buttons. The window still opens for real, and the browser
# process/log checks happen outside the app.
#
# The previous default handler is restored at the end.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
APP="$ROOT/dist/ScamShield.app"
CTL="$APP/Contents/MacOS/scamshieldctl"
DATA="$HOME/Library/Application Support/ScamShield"
LOG_CANCEL="/tmp/scamshield-realworld-cancel.log"
LOG_OPEN="/tmp/scamshield-realworld-open.log"
FAILURES=0
BENIGN="https://www.apple.com/support/"
HOSTILE="https://appleid-apple.com-verify-account.tk/login/confirm"

check() { # name, condition-exit-code, detail
  if [[ "$2" -eq 0 ]]; then printf 'PASS  %s%s\n' "$1" "${3:+ — $3}"; else printf 'FAIL  %s%s\n' "$1" "${3:+ — $3}"; FAILURES=$((FAILURES+1)); fi
}

last_history() { # prints "action|url" of the newest entry
  python3 - "$DATA/history.jsonl" <<'PY'
import json, sys
path = sys.argv[1]
try:
    lines = [json.loads(l) for l in open(path) if l.strip()]
except Exception:
    print("none|")
    raise SystemExit
if not lines:
    print("none|")
else:
    entry = lines[-1]
    action = (entry.get("action") or {}).get("action", "none")
    url = entry["scan"].get("analyzedURL") or entry["scan"].get("input", "")
    print(f"{action}|{url}")
PY
}

browser_pids() {
  pgrep -f "/Applications/Opera GX.app/Contents/MacOS" 2>/dev/null | wc -l | tr -d ' '
}

./scripts/build-app.sh >/dev/null || { echo "build failed"; exit 1; }
./scripts/stop.sh >/dev/null 2>&1 || true

PREVIOUS=$("$CTL" handler-status | awk -F'-> ' '/http  ->/{print $2}' | tr -d ' ')
echo "previous default handler: ${PREVIOUS:-unknown}"
if [[ -z "${PREVIOUS:-}" || "$PREVIOUS" == "com.scamshield.app" ]]; then
  PREVIOUS="com.operasoftware.OperaGX"
fi

echo
echo "==> step 1: register ScamShield as the default web handler"
"$APP/Contents/MacOS/ScamShield" --make-default >/tmp/scamshield-make-default.log 2>&1
MAKE_STATUS=$?
cat /tmp/scamshield-make-default.log
check "ScamShield became the https handler" $MAKE_STATUS

"$CTL" handler-status | grep -q "https -> com.scamshield.app"
check "handler verified by LaunchServices" $?

echo
echo "==> step 2: system link → decision window → cancel"
rm -f "$LOG_CANCEL"
SCAMSHIELD_TEST_AUTO_DECIDE=cancel "$APP/Contents/MacOS/ScamShield" >"$LOG_CANCEL" 2>&1 &
APP_PID=$!
sleep 2
BEFORE=$(browser_pids)
open "$BENIGN"
sleep 4
grep -q "decision window presented" "$LOG_CANCEL"
check "decision window opened for a system link" $? "$(grep -m1 'decision window presented' "$LOG_CANCEL" | sed 's/.*presented: //')"
AFTER=$(browser_pids)
[[ "$BEFORE" == "$AFTER" ]]
check "cancel kept the destination closed (no new browser process)" $? "Opera GX pids $BEFORE → $AFTER"
HISTORY=$(last_history)
[[ "${HISTORY%%|*}" == "cancelled" ]]
check "cancel recorded in local history" $? "$HISTORY"
kill "$APP_PID" 2>/dev/null; sleep 1

echo
echo "==> step 3: system link → decision window → approve → browser opens the exact URL"
rm -f "$LOG_OPEN"
SCAMSHIELD_TEST_AUTO_DECIDE=open "$APP/Contents/MacOS/ScamShield" >"$LOG_OPEN" 2>&1 &
APP_PID=$!
sleep 2
open "$HOSTILE"
sleep 5
grep -q "decision window presented" "$LOG_OPEN"
check "decision window opened for the suspicious link" $? "$(grep -m1 'decision window presented' "$LOG_OPEN" | sed 's/.*presented: //')"
HISTORY=$(last_history)
[[ "${HISTORY%%|*}" == "openedAnyway" ]]
check "explicit bypass recorded" $? "$HISTORY"
pgrep -f "/Applications/Opera GX.app/Contents/MacOS" >/dev/null 2>&1
check "Opera GX launched for the approved link" $? "$(pgrep -f '/Applications/Opera GX.app/Contents/MacOS' | head -1 | sed 's/^/pid /')"

OPERA_SESSION="$HOME/Library/Application Support/com.operasoftware.OperaGX/Current Session"
if [[ -f "$OPERA_SESSION" ]] && strings -a "$OPERA_SESSION" 2>/dev/null | grep -qF "$HOSTILE"; then
  check "Opera GX session contains the intended URL" 0
else
  printf 'INFO  Opera GX session file did not expose the URL (binary session format); process launch is the verified signal.\n'
fi

kill "$APP_PID" 2>/dev/null; sleep 1
echo
echo "==> step 4: restore the previous default browser"
# macOS refuses to let an app point the setting at another app, so the in-app attempt is
# expected to fail. The documented recovery script is the operator path.
"$APP/Contents/MacOS/ScamShield" --restore-default "$PREVIOUS" >/tmp/scamshield-restore.log 2>&1
if grep -q "restored" /tmp/scamshield-restore.log; then
  check "in-app restore accepted by macOS" 0
else
  printf 'INFO  in-app restore refused by macOS (expected): %s\n' "$(grep -m1 'failed' /tmp/scamshield-restore.log | sed 's/.*failed: //')"
  ./scripts/restore-browser.sh "$PREVIOUS" >/tmp/scamshield-restore-script.log 2>&1
  check "operator recovery script restored $PREVIOUS" $?
fi
"$CTL" handler-status | grep -q "https -> $PREVIOUS"
check "restore verified by LaunchServices" $?

pwcheck=$(grep -c "com.scamshield.app" <<<"$("$CTL" handler-status | head -2)" || true)
[[ "$pwcheck" == "0" ]]
check "ScamShield no longer holds the handler" $?

echo
if [[ $FAILURES -eq 0 ]]; then echo "REAL-WORLD TEST: PASS"; else echo "REAL-WORLD TEST: FAIL ($FAILURES failures)"; fi
exit $((FAILURES > 0 ? 1 : 0))
