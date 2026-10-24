# Test report

Environment: macOS 27.0.1 (arm64), Apple Swift 6.4, Xcode command line tools.
Workspace: `/Users/anukaranhiran/Documents/softwares/main`.
All results below are from commands run in this workspace on 2026-10-23, after a clean
`./scripts/build-app.sh`. Nothing here is projected or estimated.

## Automated

| Command | Result |
|---|---|
| `swift test` | **30 tests, 0 failures** (11 storage/media + 19 scanner) |
| `scamshieldctl eval` | **32/32 fixtures detected**, precision 1.00, recall 1.00, 0 false positives, 0 false negatives |
| `./scripts/doctor.sh` | **no failures** (bundle, signature, URL schemes, scanner self-test, API, token perms) |
| `./scripts/integration-test.sh` | **PASS** — 11/11 checks |
| `./scripts/real-world-test.sh` | **PASS** — 11/11 checks |
| `./scripts/extension-test.sh` | **PASS** — 10/10 checks |

### `integration-test.sh` (real app process, stub browser)

Real URL delivery into `application(_:open:)`, real scan, real decision window, real handoff.

```text
PASS  stub browser resolvable — Handoff Probe
PASS  decision window visible for benign link
PASS  no browser handoff before decision
PASS  cancel recorded — cancelled
PASS  cancel opened nothing
PASS  suspicious link held high risk — CRITICAL
PASS  handoff delivered exact URL — open=https://appleid-apple.com-verify-account.tk/login/confirm
PASS  bypass recorded — openedAnyway
PASS  garbage input is UNVERIFIED
PASS  file:// scheme refused
PASS  refusal explained to user
INTEGRATION TEST: PASS
```

The stub browser writes every URL it is asked to open to a log, so "opened" and "stayed
closed" are separate observed facts, not inferences from the UI.

### `real-world-test.sh` (real macOS handler, real `open`)

This registers ScamShield through `NSWorkspace.setDefaultApplication` from inside the bundle
(the only path macOS honours), then uses plain `open <url>` — the exact LaunchServices call
WhatsApp, Mail, Slack and Discord make for external links.

```text
previous default handler: com.operasoftware.OperaGX
PASS  ScamShield became the https handler
PASS  handler verified by LaunchServices
PASS  decision window opened for a system link — https://www.apple.com/support/ verdict=LOW RISK score=0
PASS  cancel kept the destination closed (no new browser process) — Opera GX pids 1 → 1
PASS  cancel recorded in local history — cancelled|https://www.apple.com/support/
PASS  decision window opened for the suspicious link — …tk/login/confirm verdict=CRITICAL score=100
PASS  explicit bypass recorded — openedAnyway|…tk/login/confirm
PASS  Opera GX launched for the approved link — pid 10013
INFO  Opera GX session file did not expose the URL (binary session format)
INFO  in-app restore refused by macOS (expected): NSCocoaErrorDomain 256
PASS  operator recovery script restored com.operasoftware.OperaGX
PASS  restore verified by LaunchServices
PASS  ScamShield no longer holds the handler
REAL-WORLD TEST: PASS
```

Notes on the two INFO lines:

- The browser's `Current Session` file is a binary format; the process launch is the verified
  signal that the approved URL was handed off. The exact-URL guarantee is covered by the
  stub-browser test above, which logs the precise string it received.
- macOS 26/27 deliberately refuses to let one app point the default-browser setting at
  *another* app, so the in-app "restore" fails by design. `scripts/restore-browser.sh`
  rewrites the LaunchServices handler records instead; that is the documented recovery path
  and it restored Opera GX successfully in every run.

The test hook `SCAMSHIELD_TEST_AUTO_DECIDE=cancel|open` only exists so a shell script can
press the button a human would press; it is inert unless the launching shell sets it.

### `extension-test.js` (real Chromium, real MV3 extension)

`extensions/chrome` is loaded into an isolated Chromium profile (Chrome for Testing from the
local Playwright cache) with the real app running. No mocking.

```text
PASS  extension service worker loaded
PASS  extension reached the local scanner — {"api":"1","app":"ScamShield","version":"1.0.0"}
PASS  benign page not blocked — http://127.0.0.1:54195/
PASS  hostile navigation intercepted — chrome-extension://…/block.html
PASS  block page shows the verdict — CRITICAL ScamShield stopped this page …
PASS  block page names the destination
PASS  blocked host persisted — ["appleid-apple.com-verify-account.tk"]
PASS  declarativeNetRequest rule registered — 1 rule(s)
PASS  repeat visit blocked before load (DNR rule) — chrome-extension://…/block.html
PASS  app recorded the extension heartbeat — [{"browser":"Chrome",…}]
EXTENSION TEST: PASS
```

This covers both extension layers: the in-browser scan that replaces a never-seen hostile
page with the warning, and the declarativeNetRequest rule that stops a known hostile host
*before* the request goes out.

### Reliability checks

| Scenario | Observed result |
|---|---|
| Preferred API port 47613 already held by another process | app bound **47614**; `run.sh` found it and printed "port 47613 was busy — the app saved 47614"; `/scan` answered on the fallback port; `settings.json.apiPort` was updated so the extension popup shows the right value |
| Second launch while one instance runs | still exactly **one** process; the new launch activates the existing window and exits (guard in `AppDelegate` + `LSMultipleInstancesProhibited`), so two copies cannot interleave history writes or fight over the API port |
| `build-app.sh` / `install.sh` / `run.sh` while Opera GX is the default browser | handler stayed **Opera GX** at every step — launching the app never claims the role |
| Idle for 60 s with the app running | handler stayed **Opera GX**; nothing re-registers on the protection refresh timer |
| `integration-test.sh` run repeatedly back to back | PASS every time after the single-instance guard and the "wait for the old instance to exit" fix; five consecutive runs, including three in a row at the end |
| First launch of a freshly re-signed bundle | the decision-window check now polls up to 6 s instead of assuming 900 ms; it failed once on a fresh signature before this fix and has not failed since |
| Handler ownership after the test scripts | `integration-test.sh` and `real-world-test.sh` both hand http/https back to the previously configured browser if the test left ScamShield owning it; verified after every run |

## Manual verification

- Launched with the documented command (`./scripts/run.sh`): builds if needed, API answers
  on `127.0.0.1:47613`, handler status printed, dashboard appears, menu-bar shield present.
- Enabled and disabled interception from the app; status changed between *Protected* →
  *Setup required*, and the Coverage list updated to match reality.
- Cancelled and "opened anyway" both recorded in History with the destination and verdict.
- Extension API probed with curl: `/health` 200, `/scan` without a token **401**, authorized
  `/scan` returns `block: true` with `displayVerdict: CRITICAL`, `/heartbeat` recorded.
- Screenshots in `docs/screenshots/` are rendered by the app itself (`--screenshot`), so they
  show this build's real state — including "Setup required", because that was true when the
  capture ran.
- Doctor run confirms the machine was left with Opera GX as the default web handler and
  ScamShield running in the menu bar with interception off.

## Not verified

- **WhatsApp Desktop's UI was not driven.** WhatsApp is installed and it opens external links
  through LaunchServices, which is exactly the path exercised by `open`. No click inside
  WhatsApp was performed, so the end-to-end claim is "the macOS route WhatsApp uses", not
  "a click inside WhatsApp".
- **Opera GX's own extension store/profile** was not used. Blocking was proven in Chromium
  with the same extension package; loading it once in Opera GX should be confirmed by watching
  the heartbeat appear in Protection Center.
- **Safari**: no Safari Web Extension is shipped. Building one requires Xcode's Safari
  extension converter and a signed app extension; see `docs/SAFARI.md`.
- **Not notarised.** Ad-hoc signature only, so another Mac needs right-click → Open.
