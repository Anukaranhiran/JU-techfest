#!/bin/bash
# Recommended way to launch ScamShield: builds if needed, starts it, verifies the scanner
# and the extension API respond, then leaves it running in the menu bar.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP="$ROOT/dist/ScamShield.app"
PORT="${SCAMSHIELD_PORT:-47613}"

if [[ "${1:-}" == "--rebuild" || ! -d "$APP" ]]; then
  "$ROOT/scripts/build-app.sh" || exit 1
fi

if pgrep -f "$APP/Contents/MacOS/ScamShield" >/dev/null 2>&1; then
  echo "ScamShield is already running — bringing up the dashboard."
  open "$APP"
else
  echo "==> starting ScamShield"
  open "$APP" || { echo "could not launch $APP" >&2; exit 1; }
fi

# ScamShield falls back to the next 7 ports if the preferred one is busy, so probe the
# whole range instead of assuming the default.
find_port() {
  local candidate
  for candidate in $(seq "$PORT" $((PORT + 7))); do
    if curl -fsS --max-time 1 "http://127.0.0.1:$candidate/health" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

LIVE_PORT=""
for _ in $(seq 1 40); do
  if LIVE_PORT="$(find_port)"; then break; fi
  sleep 0.25
done

echo
if [[ -n "$LIVE_PORT" ]]; then
  echo "scanner API:  OK on 127.0.0.1:$LIVE_PORT"
  if [[ "$LIVE_PORT" != "$PORT" ]]; then
    echo "  (port $PORT was busy — the app saved $LIVE_PORT; the extension popup shows the same value)"
  fi
else
  echo "scanner API:  NOT responding on ports $PORT-$((PORT + 7))"
  echo "  - see $HOME/Library/Application Support/ScamShield for settings and history."
fi

"$ROOT/dist/ScamShield.app/Contents/MacOS/scamshieldctl" handler-status

echo
echo "Protection state lives in the app window (menu bar shield → Open ScamShield)."
echo "To stop:   ./scripts/stop.sh"
echo "To uninstall: ./scripts/uninstall.sh"
