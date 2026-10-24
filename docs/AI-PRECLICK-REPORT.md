# AI analysis, URL input and pre-click verification

> **Update (2026-10-24):** the Gemini integration now performs real model
> discovery, filtering, candidate probing, automatic selection and bounded fallback.
> The hardcoded `gemini-2.0-flash` assumption and the raw `models/...` endpoint bug
> are fixed. See [GEMINI-INTEGRATION.md](GEMINI-INTEGRATION.md) for the current flow,
> error meanings and the live-verification result (the configured key returned a
> quota-exhausted error, so a successful live generation is still unverified).

This continues the existing ScamShield project. It records what was already working,
what changed, and what could and could not be verified on this machine.

## 1. What was already implemented

- Deterministic URL, message, email, QR/screenshot and page-content analysis.
- SSRF-hardened fetching with DNS validation, per-redirect revalidation, TLS
  verification, timeouts and a 512 KB response cap.
- Live reputation (VirusTotal, Safe Browsing, URLhaus) with honest
  passed/failed/skipped/unavailable states.
- Page inspection for forms, off-domain actions, brand claims, pressure language,
  redirects, trackers and script patterns.
- Native pre-navigation interception through the macOS default-web-browser role.
- Decision window with cancel/open, an explicit high-risk bypass, and an in-place
  background live upgrade.
- Chrome/Opera MV3 extension with declarativeNetRequest rules for known-bad hosts.
- Optional OpenAI-compatible **explanation**, which was commentary-only.

The gap was that AI was never part of scan analysis, keys were stored in
`settings.json`, and the extension popup scan used only the structural pipeline.

## 2. What was actually changed

### AI providers and credentials

- Added `Sources/ScamShieldCore/AIAnalysis.swift`.
  - **Gemini**: `POST {base}/models/{model}:generateContent` with
    `x-goog-api-key`; parses `candidates[0].content.parts[].text`.
  - **OpenAI-compatible**: `POST {base}/chat/completions` with
    `Authorization: Bearer`; parses `choices[0].message.content`.
  - Defaults: `gemini-2.0-flash` / `gpt-4o-mini`, configurable model and base URL.
- Added `Sources/ScamShieldCore/Keychain.swift`. VirusTotal, Safe Browsing, HIBP and
  AI keys are generic passwords in the macOS login Keychain. Older plaintext keys are
  migrated once and removed from `settings.json`.
- Added a real **Test connection** button. It makes one provider request and reports
  the exact result. It does **not** enable scan analysis.
- Added a separate **Use AI analysis in live scans** switch, off by default.
- Added AI output to scan results (`aiAnalysis`), checks, sources and the SwiftUI
  result detail.

### Prompt and response safety

- The prompt contains bounded deterministic evidence, URL/redirect/form/reputation
  findings and a 1,500-character plain-text page excerpt. Raw HTML, scripts, passwords
  and files are never sent.
- Page text is placed between explicit “untrusted data” delimiters. The system message
  forbids following instructions inside it; common forged instruction lead-ins are
  stripped.
- The response must be a JSON object with a valid `assessment`, `confidence` and
  `summary`. Titles/details are truncated and control characters removed.
- AI can **only add** corroborating evidence. It cannot remove deterministic evidence,
  lower a score/level, or force HIGH on its own. A provider outage is recorded as
  skipped/unavailable/failed, never as clean.

### URL input

`ScanAnythingView` now uses a fixed-height, wrapping `NSTextView` editor instead of a
single-line field. A 178-character URL wraps inside a 62-point box, the split view and
Scan button do not move, Return scans, Option-Return inserts a newline, and the text is
retained after a failed scan. Rendered with `--render-url-ui` (see verification).

### Pre-click protection

- Native: the macOS handler path still holds the link before any browser opens. Cancel
  keeps it closed. “Open anyway” is an explicit high-risk bypass. When a scan did not
  complete the button is labelled **Skip Scan & Open Anyway** and states that this is
  not a safety result.
- Pending decisions now show that live page inspection is running and update in place
  when redirect/reputation/page/AI evidence arrives.
- Extension: automatic navigation checks remain fast/structural. Known-bad hosts are
  redirected by DNR before load. A manual **Scan this tab** now requests the full live
  pipeline (`live: true`, up to 45 s). If the app is unreachable or times out, the
  extension redirects the tab to the UNVERIFIED warning page instead of silently
  continuing.
- The extension still cannot cancel a first-time navigation that has already started.
  That limitation is unchanged and documented; no universal in-app webview
  interception is claimed.

## 3. Was AI verified with a real request?

**No live AI request was made on this machine.** No Gemini, OpenAI-compatible or other
AI key was present in the Keychain or settings, and no key was available in the
environment. ScamShield correctly reports that state instead of pretending to analyse.

What *was* verified without a provider:

- Gemini and OpenAI-compatible endpoint construction, including a base URL that already
  ends in `/chat/completions`.
- Strict rejection of unstructured/missing AI responses.
- Prompt bounding and removal of forged “ignore previous instructions” text.
- AI findings cannot downgrade a deterministic HIGH/CRITICAL result.
- AI-only suspicion stays at MEDIUM, below HIGH.
- Rate-limit failure is recorded as `unavailable`, with no AI evidence.
- Keychain round-trip (write/read/delete) succeeds through `KeychainStore`.

Capability remaining unverified: an end-to-end request against a real Gemini or
OpenAI-compatible account, and the visual AI section with a real model response.

## 4. Supplied target

Rechecked on 2026-10-24:

```
DNS: https://pjz22i41in.loclx.io -> us.loclx.io / 45.55.35.48
HTTP: 404 Not Found
Title: 404 TUNNEL NOT FOUND
```

Live ScamShield result:

```
verdict: INCONCLUSIVE
risk:    28/100
evidence: LocalXpose relay +22, machine-generated hostname +6, HTTP 404 +0
checks: Page content inspection failed; page content available failed;
        trustworthy content failed; reputation skipped (no key)
```

The intended phishing page is still not served, so **no live page-level phishing
detection is claimed**. The local fixture still reaches CRITICAL when the same page is
available.

## 5. Verification run

### Live

| Check | Result |
|---|---|
| Supplied URL (HTTP) | 404 `TUNNEL NOT FOUND` |
| Supplied URL (ScamShield live) | INCONCLUSIVE 28/100, page unavailable |
| `scamshieldctl selftest` | PASS |
| `scamshieldctl eval` | 32/32, precision/recall 1.00 (synthetic fixtures) |

### Native UI / pre-click

`./scripts/integration-test.sh` — PASS:

- decision window visible before handoff,
- cancel recorded and no browser opened,
- suspicious link held CRITICAL,
- explicit bypass recorded as `openedAnyway`,
- exact URL handed to the stub browser only after approval,
- garbage input UNVERIFIED and non-web scheme refused.

### Browser extension

`./scripts/extension-test.sh` — PASS in Chromium:

- extension reached the local app,
- benign page not blocked,
- hostile navigation replaced with `block.html`,
- block page showed CRITICAL and the destination,
- host persisted and a DNR rule was registered,
- repeat visit blocked before load by the DNR rule,
- heartbeat recorded.

This verifies real browser blocking in an isolated Chromium profile. It does not claim
first-time pre-navigation cancellation; that is the documented MV3 limitation.

### Deterministic fixtures

| Fixture | Result |
|---|---|
| Fake branded login, off-domain credential POST, urgency | CRITICAL |
| Same page on a non-relay host | HIGH/CRITICAL |
| Benign official login | LOW |
| Ordinary same-host login | LOW |
| Legitimate tunnel page | not HIGH |
| Suspicious language without credentials | MEDIUM, below HIGH |
| Brand mention without a form | LOW |
| Failed fetch / HTTP 404 | INCONCLUSIVE |
| AI rate limit | AI check `unavailable`, no AI evidence |
| AI says “none” on a deterministic HIGH result | HIGH retained |

### Tests / build

```
swift test              → 69 tests, 0 failures
swift build             → Build complete
./scripts/build-app.sh  → Build complete, signature verifies
```

## 6. Remaining limitations and unverified capabilities

- No live AI provider request was possible without a key. Request shapes, validation
  and merge behaviour are covered by tests; a real account call remains unverified.
- Custom AI base URLs still go through the SSRF policy. `127.0.0.1` and private
  addresses are refused, so a local LLM on localhost is not supported.
  This preserves the existing SSRF boundary.
- The extension cannot stop a first-time MV3 navigation before it starts. Known-bad
  hosts are stopped by DNR before load on repeat visits; the first visit is a fast
  replacement after the request begins.
- The target URL is still a 404 tunnel, so live phishing detection of that exact page
  cannot be demonstrated.
