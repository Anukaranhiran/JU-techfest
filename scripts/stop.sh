#!/bin/bash
# Stops the ScamShield instance this repository built. Only processes whose command line
# points at this bundle are touched; nothing else on the system is signalled.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATTERN="$ROOT/dist/ScamShield.app/Contents/MacOS/ScamShield"

PIDS="$(pgrep -f "$PATTERN" 2>/dev/null || true)"
if [[ -z "$PIDS" ]]; then
  echo "ScamShield is not running (no process for $PATTERN)."
  exit 0
fi

for pid in $PIDS; do
  echo "==> stopping pid $pid"
  kill "$pid" 2>/dev/null || true
done

for _ in $(seq 1 20); do
  if ! pgrep -f "$PATTERN" >/dev/null 2>&1; then
    echo "stopped."
    exit 0
  fi
  sleep 0.2
done

echo "ScamShield did not exit; sending SIGKILL to $PIDS" >&2
for pid in $PIDS; do kill -9 "$pid" 2>/dev/null || true; done
