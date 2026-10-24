# Landing-page inspection and URL-level consistency

Date: 2026-10-24
Workspace: `/Users/anukaranhiran/Documents/main3/main`

This report covers the fix for inconsistent verdicts between the Website Safety
Checker and the Link/Message Checker, and the new static inspection of landing-page
navigation targets (Visit buttons, anchors, data attributes, meta refresh and literal
JavaScript navigation). It does not change the UI, the network safety boundary, the
licence notices or any unrelated feature.

## 1. Exact root cause

There were two independent defects.

1. **The Website Safety Checker used a different pipeline.** `AppModel.inspectWebsite`
   called `PageInspector.inspect(url)` and then `engine.scanURL(url)` followed by
   `applyingPageInspection`. It never called `liveScan`, so it skipped reputation
   merging, redirect tracing and the higher-level live composition used by the Link
   Scanner. The extension popup also called `liveScan`, while automatic extension
   navigation used the offline pipeline. Equivalent destinations did not receive
   equivalent URL-level analysis.
2. **Page inspection stopped at the submitted document.** `PageInspector` parsed
   forms, scripts, iframes and images, but it ignored anchors, buttons, `data-*`
   navigation attributes, meta refresh and literal JavaScript navigation. A landing
   page could therefore say one thing in its visible button and send the visitor
   somewhere else, and the scanner would never record that destination, let alone
   inspect it.

The fix keeps scoring deterministic. No URL is hardcoded, no verdict is forced, and
no fixture contains an expected label.

## 2. What changed

| File | Change |
|---|---|
| `Sources/ScamShieldCore/PageInspector.swift` | Adds `DiscoveredDestination` and `DestinationInspection`. Statically discovers anchors, buttons, navigation `data-*` attributes, meta refresh and literal `location`/`window.open` URLs. Fetches up to three external destinations through `SafeFetcher`, reusing the existing SSRF, TLS, redirect, timeout and 512 KB response-size limits. Forms are never submitted and scripts are never executed. |
| `Sources/ScamShieldCore/ScanMerger.swift` | Adds `liveScanDetailed` as the single live pipeline returning both the result and the page inspection. `liveScan` is now a wrapper. Destination evidence is merged under `landing.*`, each destination gets an attributed `Destination · host` check, and high-risk floors apply only to observed combinations (misleading/concealed navigation to a look-alike, or a fetched fake-login/harvest page). |
| `Sources/ScamShieldCore/Scanner.swift` | Adds `liveScanMessage`, `liveScanEmail`, `liveScanQRImage`, `liveScanScreenshot` and `mergeLiveLink`. Embedded links run the same live URL pipeline; message evidence stays under `text.*` and URL evidence is prefixed `link.*` / `email.link.*`. |
| `Sources/ScamShield/AppModel.swift` | Website Safety Checker now calls `liveScanDetailed`. Message, email and image UI paths use live scans when live checks are enabled. Automatic extension scans use live for public web pages; loopback/private development pages keep the structural verdict because the hardened fetcher deliberately cannot fetch them and blocking local dev pages would be a false positive. |
| `Sources/scamshieldctl/main.swift` | `scan-text` and `scan-email` accept `--live`, so the packaged app can be verified through the same message/email live wrappers without the GUI. |
| `extensions/chrome/background.js` | Automatic `/scan` now uses the full live pipeline when live checks are enabled, with a 30 s navigation timeout. |
| `Tests/ScamShieldCoreTests/PhishingDetectionRegressionTests.swift` | New regression fixtures for a Visit-button look-alike, a JavaScript destination, a fetched fake-login destination, a benign Instagram landing page, a legitimate login, message/URL separation, an unreachable destination, and unavailable reputation providers. |

Destination discovery is intentionally conservative. It records only literal URLs in
markup; it does not execute JavaScript, follow form actions, or guess runtime-computed
destinations. Those cases are reported as limitations rather than as clearance.

## 3. Before and after

The controlled fixture is an HTML page served by `httpbingo.org/base64/...` whose
visible control is `<button data-href="https://instagram-verification.example/claim">
Visit Instagram</button>`. The destination host is a reserved `.example` name, so it is
expected to be unfetchable. This is a synthetic regression fixture, not a capture of
the user's live target.

| Path | Before | After |
|---|---|---|
| Same fixture, structure only (the Website Checker's old URL component) | **LOW 12/100** (`path.encoding`, `url.length`) | — |
| Website Safety Checker pipeline (packaged `scan-url --live`) | No destination discovery; page text alone could not support a phishing verdict | **CRITICAL 75/100** with `page.misleading-visit-label` (+22), `page.destination.brand.exactTokenWrongDomain` (+16), `page.destination.brand.comboSuffix` (+11), and the destination marked unavailable |
| Link/Message pipeline for the same landing page | Structural URL analysis only | **CRITICAL 91/100**; URL evidence is attributed as `link.page.*`, distinct from message `text.*` evidence |
| Email pipeline for the same landing page | Structural URL analysis only | **CRITICAL 100/100**; URL evidence is attributed as `email.link.page.*`; the stale “links were analysed structurally only” limitation is removed once live analysis runs |

The destination `instagram-verification.example` was **discovered but not fetched**
(it does not resolve). The result is still critical because the page itself supplies
the deceptive mapping: the label names Meta, while the recorded destination is not an
official Meta domain and carries a brand-lookalike/login shape. The unavailable fetch
is recorded as unverified, not as safety.

## 4. Destinations actually discovered and pages actually fetched

All live fixtures in this report used the packaged app
(`dist/ScamShield.app/Contents/MacOS/scamshieldctl`) at the revision described below.

| Fixture | Verdict | Destination | Fetch result |
|---|---|---|---|
| Visit button → reserved look-alike | CRITICAL 75/100 | `instagram-verification.example` | Not reachable; marked unavailable, not safe |
| JavaScript `window.location.replace` → look-alike | HIGH 50/100 | `paypal-account-check.example` | Not reachable; `page.concealed-navigation` (+12) plus brand destination evidence |
| Landing page → fetched fake PayPal login | CRITICAL 100/100 | `httpbin.org` (the controlled fixture host) | **HTTP 200, 246 bytes, password form: true, brand impersonation: true**; evidence attributed as `landing.page.*` |
| Benign landing page → official Instagram | LOW 18/100 | `www.instagram.com` | **HTTP 200**, no password form, no impersonation; the score comes from the long percent-encoded harness URL, not from Instagram |
| Legitimate same-host login form | LOW 18/100 | `httpbingo.org` (same host as fixture) | **HTTP 200**; password form submits to the page's own host |
| HTTP 404 | INCONCLUSIVE 0/100 | `httpbingo.org/status/404` | 404; failed content check; no phishing claim |
| Unresolvable host | INCONCLUSIVE 7/100 | `this-host-should-not-exist-zz9.example` | Resolution failure; structural context only |

The fake-login destination check reported:

```text
Destination · httpbin.org — HTTP 200; 246 bytes; password form: true; brand impersonation: true.
```

The destination evidence was:

```text
[+22] landing.page.brand-impersonation
[+18] landing.page.external-form
[+17] landing.page.credential-pressure-combo
[+15] landing.page.password-form
```

The full machine-readable output is in `docs/landing-page-live-after.json`.

## 5. External scanner investigation (urlscan.io)

The official urlscan.io API documentation was reviewed. Submission requires an API
key, and a normal submission creates a public scan result visible to third parties;
private scans require a paid arrangement. No urlscan.io API key is present in this
project, and the app has no user-facing consent step for publishing a URL to a third
party.

Because of that, no urlscan.io integration was added. Reporting one would have been a
fake integration. The local scanner was improved instead. The local pipeline remains
the authoritative engine. If urlscan.io is added later, it must be opt-in, disclosed,
attributed separately, and must not overwrite deterministic findings.

## 6. Tests and build

```text
swift test                 → 93 tests, 0 failures
swift build -c release     → Build complete
./scripts/build-app.sh     → app bundle built, ad-hoc signature verifies
scamshieldctl selftest     → PASS
scamshieldctl eval         → 32/32 fixtures, precision 1.00, recall 1.00,
                             0 false positives, 0 false negatives
./scripts/integration-test.sh → INTEGRATION TEST: PASS
./scripts/extension-test.sh   → EXTENSION TEST: PASS (10/10 checks)
```

The extension test explicitly verifies:

- a benign localhost page is **not** blocked;
- a hostile navigation is replaced by the block page;
- the warning names the destination;
- the blocked host and declarativeNetRequest rule are persisted;
- a repeat visit is blocked before load;
- the app records the extension heartbeat.

The regression suite prints the fixture outcomes, including:

```text
FIXTURE Visit button → lookalike: CRITICAL 77/100
FIXTURE JavaScript destination: HIGH RISK 50/100
FIXTURE fetched fake-login destination: HIGH RISK 50/100
FIXTURE benign Instagram landing: LOW RISK 6/100
FIXTURE legitimate login: LOW RISK 6/100
FIXTURE message + live URL: CRITICAL 100/100
```

The live packaged numbers above differ from the synthetic unit fixtures because the
packaged fixtures are served through a long percent-encoded public relay URL, which
adds its own URL-structure evidence. That is an honest property of the harness, not a
tuned result.

## 7. Remaining limitations

- **No user-supplied live target was available.** No real suspicious URL was present
  in the workspace or conversation, so no claim is made that the user's original site
  was reproduced. The earlier authorized `loclx.io` endpoint still returned HTTP 404,
  which is unavailable, not proof of safety or phishing.
- Client-side destinations computed at runtime, destinations inside external
  JavaScript bundles, and pages reachable only after interaction remain undiscovered
  by static inspection. The app does not execute untrusted scripts in its privileged
  process.
- At most three external destinations per landing page are fetched. Anchor URLs,
  form actions, meta refresh and literal JavaScript are recorded, but form actions are
  not submitted and no authentication is attempted.
- A destination that fails to resolve, times out or returns 404 is reported as
  unverified. It never becomes a clean result.
- No reputation provider or AI key is configured. Reputation checks are skipped and
  do not erase strong observed page evidence.
- Automatic extension scans intentionally use the structural verdict for
  loopback/private development pages, because the safe fetcher is not allowed to
  inspect them. An explicit popup scan still reports live inspection as unavailable.
- The controlled fixtures prove behaviour on synthetic documents. They are not a
  measurement of real-world accuracy.

## 8. Domain registration age update

The live URL pipeline now merges the existing RDAP registration check after redirect
tracing and page inspection, so the Website Safety Checker, Link Scanner, extension,
message, email, QR and screenshot paths share one age rule.

- If RDAP publishes a creation timestamp less than **1 hour** old, ScamShield records
  `domain.registered-under-1-hour` as **“Highly suspicious”** with weight **+50**.
  That alone can reach HIGH risk, but never CRITICAL, so age alone does not confirm
  phishing.
- Creation timestamps between 1 hour and 30 days keep the existing newly-registered
  evidence (+24); 31–90 days keeps +12; older domains keep the contextual −4.
- If RDAP is unavailable, has no record, or publishes no creation timestamp, the
  `Domain registration age` check is **unavailable** and the limitation says the age
  is unknown, not a clearance. No age is invented.
- RDAP requests use the existing `SafeFetcher` boundary. No new provider or API key
  was added.

Focused verification:

```text
17-minute-old fixture → HIGH 64/100 (not CRITICAL)
2.5-hour-old fixture  → newly-registered evidence, below HIGH
missing timestamp     → unavailable check, no age evidence
live example.com      → RDAP confirms 11,393 days old
reserved .example     → RDAP unavailable, reported honestly
```
