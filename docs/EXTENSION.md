# Chrome / Opera GX extension

The extension is a secondary layer. It adds pre-navigation warnings for links clicked
*inside* the browser, which the system handler can never see.

## Install

1. Start ScamShield: `./scripts/run.sh`
2. In ScamShield open **Settings → Extension API** and copy the **port** (default 47613) and **token**.
   The token is per-install, stored with mode 600 at
   `~/Library/Application Support/ScamShield/api-token`.
3. Load the unpacked extension:
   - **Chrome**: `chrome://extensions` → enable *Developer mode* → *Load unpacked* →
     select `extensions/chrome` (or `ScamShield.app/Contents/Resources/extensions/chrome`).
   - **Opera GX**: `opera://extensions` → *Developer mode* → *Load unpacked* → same folder.
4. Open the ScamShield popup, paste port + token, press **Save & test**.
   The badge should read *connected*.
5. Confirm in ScamShield → Protection Center: "Browser extensions" should list
   "Chrome 1.0.0" / "Opera GX 1.0.0" as connected. That line is driven by real
   heartbeats, not a boolean in settings.

## What it does

Two mechanisms, both fed by the local scanner:

1. **`declarativeNetRequest` rules** for hosts already seen as high/critical.
   These redirect the main-frame navigation to `block.html` *before* the page loads —
   genuine pre-navigation blocking, stored per browser profile (max 200 domains).
2. **`webNavigation.onBeforeNavigate`** for everything else. It asks
   `POST /scan` with the fast structural pipeline; if the verdict requires a bypass, the
   tab is replaced with the warning page and the decision is recorded locally. A manual
   **Scan this tab** from the popup sends `live: true`, so redirects, reputation, page
   inspection and configured AI analysis run for that explicit scan.

Chrome MV3 cannot cancel a navigation that has already started; the replacement happens
within milliseconds and the destination may still receive a request. This is stated on the
warning page and in the README rather than presented as a guarantee.

## Warning page

- destination URL, verdict, score, evidence with weights, limitations,
- **Keep it closed** (closes the tab) — the destination stays closed,
- **Open anyway** — records the explicit bypass in ScamShield history, stops blocking that
  host for 10 minutes, then navigates.

If the scanner is unreachable the page still appears and says **UNVERIFIED**, never "safe".

## API contract

All endpoints are on `127.0.0.1` only. Every call except `/health` needs
`X-ScamShield-Token`. CORS is allowed because the token is the authority.

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/health` | — | liveness + version (no secrets) |
| POST | `/scan` | `{url, browser}` | verdict JSON; adds `block: true` for high/critical |
| POST | `/heartbeat` | `{browser, version}` | records that this browser is connected |
| POST | `/open` | `{url, browser}` | records an explicit user bypass |

## Security notes

- The listener binds `127.0.0.1` only; there is no LAN exposure.
- Bodies are capped (512 KiB), reads time out after 5 s, token comparison is constant-time.
- The token is never placed in page context, never in a URL, and never leaves the machine.
- A web page cannot call the API successfully without the token.

## Troubleshooting

| Symptom | Cause |
|---|---|
| popup says *offline* | ScamShield not running, or it bound a later port because 47613 was busy (Settings shows the real port) |
| *connected* but no heartbeats in Protection Center | you saved a token that does not match `api-token` on disk |
| warning page loops | the host is still in the dynamic rule set; press *Open anyway* or clear `blockedHosts` in `chrome.storage.local` |
| no interception at all | extension disabled, or the navigation is inside an iframe/extension page (main-frame only by design) |

## Verification status

The extension has been loaded into a real Chromium (`node scripts/extension-test.js`, an
isolated throwaway profile, real app running) and observed to:

- leave a benign page untouched,
- replace a never-seen hostile URL with its warning page showing the app's verdict,
- remember that host as a declarativeNetRequest rule that stops the *next* visit before the
  request leaves the browser,
- reach the app, which recorded the heartbeat.

What is still unverified is the extension inside Opera GX's own profile and the Chrome Web
Store installation path. Load it once from `chrome://extensions` (Developer mode → *Load
unpacked* → `extensions/chrome`), paste the port and token from ScamShield › Settings, and
watch *Browser extensions* turn green in Protection Center.
