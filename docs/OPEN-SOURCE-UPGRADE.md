# Open-source detection upgrade

Date: 2026-10-24
Project: `/Users/anukaranhiran/Documents/main3/main`

This is an implementation report, not a proposal. It records the repositories
reviewed, what was actually adapted, the detection changes, the independent labelled
baseline, build/test results, the frozen source hash, and what remains unverified.

## 1. Repositories inspected

| Repository | Revision | Licence | Outcome |
|---|---|---|---|
| [PhishLens](https://github.com/Georgefifth/phishlens) | `b85f7c6` | MIT (`LICENSE` present) | **Adapted** selected URL/page heuristics into Swift |
| [URL Reputation Checker](https://github.com/newuni/url-reputation) | `be8e165` | MIT | Reviewed; no code copied. Its provider score weighting overlaps existing evidence scoring and provider-state handling |
| [PhishShield](https://github.com/SiranjeeviE/PhishShield) | `69dc24c` | **No licence file**; README only claims MIT | **Not reused.** It also relied on hardcoded phishing URL patterns and a broad trusted-domain allowlist |

PhishLens is a zero-dependency JavaScript engine with genuine explainable heuristics.
Its brand table and UI were not copied. Its algorithms were reimplemented in Swift,
with lower weights where they would double-count ScamShield's existing checks.

The required MIT notice, copyright line and list of adapted algorithms are in
`THIRD-PARTY-NOTICES.md`. `scripts/build-app.sh` copies that notice into
`ScamShield.app/Contents/Resources/THIRD-PARTY-NOTICES.md`.

## 2. Files changed and why

| File | Change |
|---|---|
| `Sources/ScamShieldCore/DeceptiveStructure.swift` | **New.** Swift ports of PhishLens character entropy, consonant-only labels, digit-stuffed/hex subdomains, fake public-suffix labels inside subdomains, embedded IPv4 subdomains and opaque base64-like path blobs. All are weak/context evidence; none bans a provider or TLD. |
| `Sources/ScamShieldCore/URLAnalyzer.swift` | Calls the new structure checks. Adds two focused combinations: a strong brand look-alike + credential path, and a brand login path on a bare public IP. |
| `Sources/ScamShieldCore/DomainUtils.swift` | **Bug fix discovered by the baseline.** The shared leetspeak fold mapped the letter `i` to `l`, so `micros0ft` became `mlcrosoft` and never matched Microsoft. It now folds `1` to both `l` and `i` and leaves letters intact. |
| `Sources/ScamShieldCore/Brands.swift` | Brand comparison checks both digit-1 folds (`paypa1`→`paypal`, `m1crosoft`→`microsoft`) instead of one broken fold. |
| `Sources/ScamShieldCore/PageInspector.swift` | Form destinations now compare **registrable domains**, so `www.example.com` → `login.example.com` is same-site while `example.com` → `collect.example.net` remains cross-site. Adds non-payment high-value field detection (SSN, OTP/2FA, PIN, seed/recovery phrase, private key) and hidden-iframe detection. |
| `Tests/ScamShieldCoreTests/SecurityRegressionTests.swift` | Six new focused tests: explainable generated-host signals, no punishment of ordinary/official hosts, registrable-domain form comparison, high-value fields + hidden iframes, benign inputs stay low, and the `i`/`l` fold regression. |
| `THIRD-PARTY-NOTICES.md` | MIT notice, exact repository/revision, scope of adaptation, and projects reviewed but not copied. |
| `scripts/build-app.sh` | Ships the notices inside the app bundle. |
| `evaluation/holdout-urls.json` | 25 labelled structural URLs (11 phishing-shaped, 1 suspicious executable download, 13 benign). |
| `scripts/baseline-compare.js` | Runs the frozen ScamShield CLI and PhishLens on the same labels, without passing labels or case IDs to either detector. |
| `evaluation/FROZEN-SOURCE.sha256` | Per-file and aggregate hash of detection/scoring sources. |

No product UI was redesigned. No sidebar tool was added.

## 3. Detection improvements demonstrated

- `paypa1.com/login` previously reached only **MEDIUM 46**. It now reaches
  **HIGH 54** through the brand-lookalike + credential-path combination.
- `micros0ft-support.top` previously reached **LOW 8**. The leetspeak bug meant it did
  not even match the brand. It now reaches **HIGH 54** with Microsoft homoglyph and
  brand-plus-pressure evidence.
- A PayPal login path on a bare public IP previously reached **MEDIUM 40**; the
  IP-plus-brand-login combination now makes it **HIGH 50**.
- A cross-site form is still reported, but a parent/subdomain form is no longer a
  false cross-site signal.
- High-value OTP/SSN/PIN/seed fields and hidden iframes now produce explicit evidence
  on an inspected page. They never run on an unavailable/404 page.
- Generated-host structure is now explainable without blanket-banning LocalXpose,
  Vercel, Cloudflare, shorteners, ordinary hosting or HTTP.

## 4. Independent labelled baseline

Data: `evaluation/holdout-urls.json` — **25 labelled cases**: 11 phishing-shaped URLs,
1 suspicious executable download, 13 benign URLs (official brands, shared hosting,
localhost, a long query, LocalXpose's own service domain, ordinary sites).
These are **synthetic/constructed URL labels, not live phishing observations**. They
measure structural behaviour and false-positive resistance, not real-world accuracy.

Command:

```bash
git clone https://github.com/Georgefifth/phishlens.git /tmp/phishlens
swift build
node scripts/baseline-compare.js /tmp/phishlens/engine.js
```

### Strict threshold (ScamShield high+, PhishLens dangerous)

Phishing-labelled rows only; benign rows are TN/FP.

| Detector | TP | FN | FP | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| ScamShield | 11 | 0 | 0 | 13 | 1.000 | 1.000 |
| PhishLens | 7 | 4 | 0 | 13 | 1.000 | 0.636 |

### Inclusive threshold (ScamShield medium+, PhishLens suspicious+)

Includes the suspicious executable-download row as a positive.

| Detector | TP | FN | FP | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| ScamShield | 12 | 0 | 0 | 13 | 1.000 | 1.000 |
| PhishLens | 11 | 1 | 0 | 13 | 1.000 | 0.917 |

Notable disagreement: the raw-IP PayPal login was `dangerous` in PhishLens but only
`medium` in ScamShield before the new combination rule; it is now `high` in both.
Conversely PhishLens scored localhost `caution 27`, while ScamShield correctly treats
loopback as local context. ScamShield also scored GitHub `low 14` because of its
dangerous-extension vocabulary? No — that result came from URL length/keyword context,
not a provider ban; it remained comfortably LOW.

The 13 benign cases produced **0 false positives** in both detectors at the inclusive
threshold. This sample is too small and too constructed to claim real-world precision.

### Page-level regression fixtures (not the independent URL baseline)

The deterministic page tests still cover: fake branded login with off-domain
credential POST and pressure language (HIGH/CRITICAL), a same page on a plain host
(HIGH), an official PayPal login (LOW), an ordinary same-host login (LOW), a
legitimate tunnel page (not HIGH), pressure text without a form (MEDIUM, below HIGH),
a brand mention without a form (LOW), and HTTP 404/failed fetch (INCONCLUSIVE).
These are project fixtures, not independent threat-intelligence samples.

## 5. Live target recheck

`https://pjz22i41in.loclx.io` was rechecked on 2026-10-24 through the real packaged
CLI with live checks:

```text
DNS:        pjz22i41in.loclx.io -> us.loclx.io / 45.55.35.48
HTTP:       404 Not Found
Title:      404 TUNNEL NOT FOUND
Redirects:  0
Body:       2,036 bytes
ScamShield: INCONCLUSIVE 34/100
Evidence:   LocalXpose relay +22, generated relay hostname +6, digit-stuffed
            subdomain +6, HTTP 404 page +0
Checks:     page content inspection failed; content availability failed;
            reputation skipped (no key); redirects passed
AI:         not called (no provider configured / analysis off)
```

The intended phishing content is still not served. **No live phishing detection is
claimed for that URL.** The result is INCONCLUSIVE because an unavailable page is not a
clearance. The new digit-stuffed finding refers to the relay hostname's own digits and
does not ban `loclx.io`; its parent domain remains LOW.

## 6. Build, tests, packaging and integration

Executed after the final code changes:

```text
swift test              -> 93 tests, 0 failures
swift build             -> Build complete
./scripts/build-app.sh  -> Build complete, signature verifies
scamshieldctl selftest  -> PASS
scamshieldctl eval      -> 32/32 built-in fixtures, precision 1.00, recall 1.00
./scripts/integration-test.sh -> PASS
./scripts/extension-test.sh   -> PASS in Chromium
```

The native integration test covered decision-before-handoff, cancel opening nothing,
CRITICAL/HIGH hold, explicit bypass, exact URL handoff, malformed input UNVERIFIED, and
`file://` refusal. The extension test covered benign navigation untouched, hostile
navigation replaced by `block.html`, destination shown, DNR rule persisted, repeat
visit blocked before load, and a heartbeat received by the app.

## 7. Providers and credentials

- VirusTotal, Google Safe Browsing, URLhaus, HIBP and AI keys remain optional.
- No provider key was configured on this machine. Reputation is recorded as skipped,
  not clean. No live AI request was made.
- Local deterministic scanning, page inspection, redirect tracing, QR decoding and
  screenshot OCR work without any key.
- Keys stay in the macOS Keychain; none are required for this upgrade.

## 8. Frozen code for the blind fresh-URL test

Detection/scoring code was frozen after the tests above and before receiving any new
URL:

- Manifest: `evaluation/FROZEN-SOURCE.sha256`
- Aggregate SHA-256 of the manifest: `025f42aa01a5f07f6cb20f6b01eb40639c7f29ed150618704f52872332d65f09`
- Freeze time: `2026-10-23T22:29:37Z` (UTC)
- Includes: URL/brand/domain analysis, page/text/email analysis, scoring/merging,
  relay handling, SafeNetwork, media, AI validation, storage/Keychain and the extension
  background worker.

No detection or scoring source file has been changed after this hash, including after
seeing the previous target's result. The previous LocalXpose URL, any future test URL,
a test-case name or a hidden expected label is **not** an input to detection and is not
hardcoded as malicious.

When a fresh URL is supplied, it will be scanned through the real packaged workflow.
If the page is unreachable, the result will be reported as INCONCLUSIVE. If a genuine
defect is found, it will be documented, fixed, and re-evaluated on a new holdout set
with a new freeze hash rather than silently patching the rule to fit the URL.

## 9. Remaining limitations / not verified

- The 25-case URL baseline is synthetic and small; it does not establish real-world
  precision or recall.
- No fresh live phishing page has been successfully retrieved yet.
- No live AI provider request was possible without credentials. AI analysis remains
  off by default and cannot erase deterministic findings or force HIGH alone.
- JavaScript is not executed during page inspection; client-rendered phishing content,
  post-interaction capture and pop-ups remain unseen.
- The extension still cannot cancel a first-time MV3 navigation before it starts.
  Known-bad repeat visits are stopped pre-navigation by DNR.
- Localhost/private LLM endpoints remain blocked by the SSRF policy.
- Email header checks depend on the pasted `Authentication-Results`; absent headers are
  reported as unchecked, never guessed.
- QR and screenshot analysis was regression-tested locally; no live malicious QR image
  was supplied.

## 10. Landing-page inspection update (2026-10-24)

The manifest above was regenerated after the landing-page work, so the aggregate hash
in section 8 is current for this revision. Details are in
`docs/LANDING-PAGE-INSPECTION.md`.

- The Website Safety Checker now calls the same `liveScanDetailed` pipeline as the
  Link Scanner, then the extension and the message/email wrappers.
- Static discovery now records external anchors, buttons, navigation `data-*`
  attributes, meta refresh and literal JavaScript navigation. Up to three external
  destinations are fetched through `SafeFetcher`; forms are never submitted and
  scripts are never executed.
- Destination evidence is attributed (`landing.*`, `link.*`, `email.link.*`) and each
  fetched page gets a `Destination · host` check. Unreachable destinations remain
  unverified and are never treated as clean.
- A benign Instagram link stays LOW; a deceptive visit control or fetched fake-login
  page can reach HIGH/CRITICAL from observed evidence, not a hardcoded URL.
- urlscan.io was reviewed but not integrated: submission needs an API key and makes
  the scan public to third parties, and this app has no consent surface for that.
- Final packaged checks: 93 Swift tests / 0 failures, 32/32 fixtures, selftest PASS,
  integration PASS, extension PASS.
