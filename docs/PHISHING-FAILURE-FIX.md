# Focused phishing-detection repair

Workspace: `/Users/anukaranhiran/Documents/main3/main` only. No sidebar, provider, UI redesign, network-policy or URL-specific detection changes.

## Live target: still blocked by missing content, not detected phishing

The exact authorized URL `https://pjz22i41in.loclx.io` was fetched through this project's existing `SafeFetcher` and redirect validation, with all reputation providers explicitly disabled and no AI. Both before and after the repair:

- HTTP **404**, title **404 TUNNEL NOT FOUND**.
- **2,036 response bytes**, no redirects; final URL is the same host/root path.
- Static text: `404 TUNNEL NOT FOUND 404 TUNNEL NOT FOUND`.
- No intended login page, credential fields or form destinations available for verification.
- Initial structure-only result: **CAUTION, 28/100** (relay evidence 22 + generated-host evidence 6). The final workspace build returns **CAUTION, 34/100**, also including `host.digit-stuffed` (+6).
- Final combined result: **INCONCLUSIVE, 34/100**, failed page-content check. The score is infrastructure context, not phishing confirmation. HTTP 404 adds zero risk weight. The earlier live probe was INCONCLUSIVE 28/100.
- No credentials submitted, page scripts executed, AI/provider requests made, keys loaded, or SSRF restrictions bypassed.

This copy has a different existing network implementation from the previously discussed workspace. The observations above are from **this copy**, not reused NAT64-block results.

Machine-readable runs: `docs/phishing-failure-live-before.json` and `docs/phishing-failure-live-after.json`. Their timestamps are UTC; the final live verification time is recorded in the latter. **The actual phishing page's historical HTML/branding cannot be reconstructed from a tunnel-not-found response.** The regression fixture is explicitly synthetic, not a claimed capture of that page. Live phishing verification remains blocked until the intended page is available or its actual HTML is supplied safely.

The workspace acquired `DeceptiveStructure.swift` during this session; its digit-stuffed signal appears in the final build. This repair did not edit that detector or `URLAnalyzer.swift`, and did not overwrite the other work. The six-point difference is not page detection and is not attributed to the form-parser repair.

## Trace and demonstrated code defects

The existing live path is `ScanEngine.scanURL` → `deepScanReputation` → `RedirectTracer.trace` → `PageInspector.inspect/analyze` → `applyingPageInspection` → optional AI. The existing Link Scanner and intercepted-link paths call this pipeline; the Website Safety Checker uses the same page inspector and merger. CLI `scan-url` without `--live` is intentionally structure-only.

This repair changed four production files:

1. **`Sources/ScamShieldCore/PageInspector.swift`**
   - Password detection relied on literal substrings such as `type="password"`, missing valid `type = "password"` HTML.
   - Attribute parsing accepted only quoted values, losing unquoted form actions. It also searched the whole form, so a nested `data-action` could be mistaken for the form destination. Parsing now reads actual opening-tag attributes and input attributes, including whitespace/unquoted variants. Missing/empty actions resolve to the current page.
   - Brand matching used unrestricted substrings and registry order: “Groups” could match UPS, and an incidental Apple mention could displace a PayPal title. Matching now uses word boundaries and prioritizes title branding. A brand mention without credential collection is not labeled impersonation.
   - Chat/message rules treated ordinary login instructions (“enter your password”, “verify your account”) as independent pressure evidence. Password forms now require genuine urgency/account-loss wording for the pressure combination; ordinary credential instructions are not counted twice.
   - Non-success/empty responses previously continued through phishing analysis, allowing an error document to masquerade as the intended page. They now stop before form/brand classification. Unsupported and truncated responses are distinguished from complete inspection.
2. **`Sources/ScamShieldCore/ScanMerger.swift`**
   - A same-page password form plus an unrelated external search/newsletter form could force HIGH. The external credential rule now relies on both facts belonging to the **same form**.
   - A 200 response alone previously marked unsupported, empty or truncated content as successfully inspected. Completion now requires actually inspected content; incomplete results stay inconclusive unless independent strong evidence already exists.
   - Subsequent merges retain existing strong score/level floors. Optional AI is not invoked on incomplete page content.
3. **`Sources/ScamShieldCore/Scanner.swift`**
   - Reputation merging recomputed the result from raw weights, discarding combination-enforced HIGH floors. A reproduced no-match result reduced HIGH 54 to CAUTION 46. Merging now preserves the prior score/level.
   - “No listing” is retained as an attributed observation with **zero** weight, not a negative score discount.
4. **`Sources/ScamShieldCore/ReputationService.swift`**
   - The equivalent aggregate no-listing observation also has zero weight, so it cannot reintroduce that discount.

No changes were made to `SafeNetwork.swift`, relay-domain rules, AI providers, app navigation or settings.

## Regression evidence: local fixtures, not live target content

`Tests/ScamShieldCoreTests/PhishingDetectionRegressionTests.swift` adds eight targeted tests. Before the fix, all eight methods failed (29 failed assertions). Existing tests were not weakened or removed.

| Fixture/check | Actual result after repair |
|---|---|
| Minimal PayPal-branded form with `type = 'password'` | **HIGH 64/100**, previously **CAUTION 40/100**; detected without AI |
| PayPal + password/email + unquoted cross-host action + suspension/urgency | **CRITICAL 100/100** on both an unrelated plain hostname and a LocalXpose fixture |
| Cross-host credential form on a zero-score URL | Combination-enforced **HIGH 50/100** retained after not-configured, unknown, error and no-match reputation outcomes; same outcome when reputation is merged first |
| Official PayPal login with ordinary instructions and unrelated search form | **LOW 0/100** |
| Non-registry login with those instructions/search form | **CAUTION 20/100**, not HIGH; residual mild form/reset context is not a clean bill of health |
| Benign LocalXpose login with unrelated search form | **CAUTION 42/100**, not HIGH; existing relay context remains |
| Existing ordinary same-host login / benign LocalXpose demo tests | Passed: ordinary login LOW; benign tunnel remains below HIGH |
| HTTP 404 containing phishing-like markup | **INCONCLUSIVE**; error-document fields are not classified as the requested page |
| Empty 200, unsupported content, truncated response | **INCONCLUSIVE**, not a passed page-content check |
| Nested `data-action`, incidental brands, “Groups” | No borrowed form destination or UPS impersonation finding |

The full branded harvesting fixture already had some independent warning signals before the patch; the specific reproduced false negative is the **minimal whitespace-password fixture**, and the field/action assertions isolate the parser defects. No claim is made that these synthetic characteristics were present on the unavailable live phishing page.

## Verification

- **51 relevant tests passed**: 19 existing scanner tests, 24 selected existing security/page/SSRF/merge tests and eight new regressions.
- The eight new regressions were also rerun after strengthening the zero-score URL/50-point-floor assertions; all passed.
- `swift build -c release` succeeded. Existing Sendable/LaunchServices warnings remain; unrelated warning cleanup was deliberately not attempted.
- Updated `dist/ScamShield.app` with the release binaries and verified its strict ad-hoc signature. No installation, app launch, default-browser change or LaunchServices registration was performed.

Relevant test command:

```sh
swift test --filter 'PhishingDetectionRegressionTests|ScannerTests|SecurityRegressionTests.test(Loclx|Relay|Benign|ProviderClean|UnavailableReputation|MaliciousProvider|Private|Disallowed|NonWeb|Typos|Embedded|Phishing|Controlled|Ordinary|Legitimate|SuspiciousLanguage|BrandMention|FailedPage|HTTPError|AIReportCannotDowngrade|AIFailure)'
swift build -c release
```

The temporary `build/PhishingFailureProbe.swift` harness reproduces the existing local live pipeline with provider keys absent/URLhaus disabled and no AI, avoiding unrelated saved integration settings. It links the real core library; it is not a replacement scanner.

Remaining limit: static markup inspection does not execute JavaScript or establish rendered visibility; dynamically generated forms and complex/malformed HTML can still evade these heuristics. The unavailable target is **not claimed detected**.
