#!/bin/bash
# Diagnoses the local installation: build, bundle registration, handler, scanner, API.
# Read-only except that it may start the CLI self-test (no system changes).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
APP="$ROOT/dist/ScamShield.app"
CTL="$APP/Contents/MacOS/scamshieldctl"
DATA="$HOME/Library/Application Support/ScamShield"
PORT=47613
FAILURES=0

say() { printf '%-38s %s\n' "$1" "$2"; }
ok() { say "$1" "OK  $2"; }
bad() { say "$1" "FAIL $2"; FAILURES=$((FAILURES+1)); }
warn() { say "$1" "WARN $2"; }

echo "ScamShield doctor"
echo "================="
say "macOS" "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
SWIFT_VERSION=$(swift --version 2>/dev/null | head -1 | cut -d'(' -f1)
say "Swift" "$SWIFT_VERSION"
say "workspace" "$ROOT"
echo

if [[ -d "$APP" ]]; then ok "app bundle" "$APP"; else bad "app bundle" "missing — run ./scripts/build-app.sh"; fi
if [[ -x "$CTL" ]]; then ok "cli" "scamshieldctl present"; else bad "cli" "missing inside app bundle"; fi

if [[ -d "$APP" ]]; then
  if codesign --verify --deep --strict "$APP" >/dev/null 2>&1; then
    ok "code signature" "verifies (ad-hoc)"
  else
    bad "code signature" "invalid — rebuild"
  fi
  URLTYPES=$(/usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes:0:CFBundleURLSchemes" "$APP/Contents/Info.plist" 2>/dev/null | tr -d '\n' | tr -s ' ')
  if [[ "$URLTYPES" == *http* && "$URLTYPES" == *https* ]]; then
    ok "url schemes declared" "http, https"
  else
    bad "url schemes declared" "Info.plist does not declare http/https"
  fi
fi

if [[ -x "$CTL" ]]; then
  STATUS=$("$CTL" handler-status)
  echo "$STATUS" | sed 's/^/    /'
  SETTINGS_JSON="$HOME/Library/Application Support/ScamShield/settings.json"
  INTERCEPTION=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('interceptionEnabled'))" "$SETTINGS_JSON" 2>/dev/null || echo "unknown")
  if echo "$STATUS" | grep -q "https -> com.scamshield.app"; then
    ok "default web browser" "ScamShield"
    if [[ "$INTERCEPTION" == "False" ]]; then
      warn "interception matches handler" "ScamShield owns http/https but interception is off in Settings. Run ./scripts/restore-browser.sh <browser-id> to hand links back."
    fi
  else
    warn "default web browser" "not ScamShield — link interception is off (enable it in the app)"
  fi

  if "$CTL" selftest >/dev/null 2>&1; then ok "scanner self-test" "PASS"; else bad "scanner self-test" "see output of: $CTL selftest"; fi
  EVAL=$("$CTL" eval 2>&1 | head -3)
  if echo "$EVAL" | grep -q "false positives: 0  false negatives: 0"; then
    ok "fixture evaluation" "no FP / FN"
  else
    bad "fixture evaluation" "$(echo "$EVAL" | tr '\n' ' ')"
  fi
fi

if pgrep -f "$APP/Contents/MacOS/ScamShield" >/dev/null 2>&1; then
  ok "app process" "running (pid $(pgrep -f "$APP/Contents/MacOS/ScamShield" | head -1))"
else
  warn "app process" "not running — start with ./scripts/run.sh"
fi

HEALTH=$(curl -fsS --max-time 1 "http://127.0.0.1:$PORT/health" 2>/dev/null || true)
if [[ -n "$HEALTH" ]]; then
  ok "extension API" "$HEALTH"
else
  warn "extension API" "no response on 127.0.0.1:$PORT (app stopped, or it bound a later port — check Settings)"
fi

if [[ -f "$DATA/settings.json" ]]; then ok "settings" "$DATA/settings.json"; else warn "settings" "not created yet (app not launched)"; fi
if [[ -f "$DATA/history.jsonl" ]]; then
  ok "history" "$(wc -l < "$DATA/history.jsonl" | tr -d ' ') entries"
else
  warn "history" "no scans recorded yet"
fi
if [[ -f "$DATA/api-token" ]]; then
  PERMS=$(stat -f "%Lp" "$DATA/api-token")
  if [[ "$PERMS" == "600" ]]; then ok "api token" "present, permissions 600"; else warn "api token" "permissions $PERMS (expected 600)"; fi
fi

if [[ -d "$APP/Contents/Resources/extensions/chrome" ]]; then
  ok "extensions bundled" "$APP/Contents/Resources/extensions/chrome"
else
  warn "extensions bundled" "missing from bundle"
fi

echo
if [[ $FAILURES -eq 0 ]]; then
  echo "doctor: no failures"
else
  echo "doctor: $FAILURES failure(s)"
fi
exit $((FAILURES > 0 ? 1 : 0))
