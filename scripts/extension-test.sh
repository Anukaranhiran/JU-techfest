#!/bin/bash
# Runs the real browser-extension test. playwright-core is a *test-only* dependency and is
# installed into a cache directory outside the project, so the product keeps zero npm deps.
#
# Requires: the app running (./scripts/run.sh) and a Chromium/Chrome binary (auto-detected,
# or set CHROME_PATH). Needs network access the first time, to fetch playwright-core.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
CACHE="${SCAMSHIELD_TEST_DEPS:-$HOME/Library/Caches/ScamShield/test-deps}"

if ! node -e "require.resolve(process.env.PLAYWRIGHT_PATH || 'playwright-core')" >/dev/null 2>&1; then
  if [[ ! -d "$CACHE/node_modules/playwright-core" ]]; then
    echo "==> installing playwright-core into $CACHE (one-time, test-only)"
    mkdir -p "$CACHE"
    (cd "$CACHE" && npm init -y >/dev/null 2>&1 && npm install playwright-core --silent) || {
      echo "could not install playwright-core (offline?). Install it manually and set PLAYWRIGHT_PATH." >&2
      exit 1
    }
  fi
  export NODE_PATH="$CACHE/node_modules${NODE_PATH:+:$NODE_PATH}"
fi

if ! curl -fsS --max-time 2 "http://127.0.0.1:${SCAMSHIELD_PORT:-47613}/health" >/dev/null 2>&1; then
  echo "ScamShield is not answering on 127.0.0.1:${SCAMSHIELD_PORT:-47613}." >&2
  echo "Start it first: ./scripts/run.sh" >&2
  exit 1
fi

node "$ROOT/scripts/extension-test.js"
