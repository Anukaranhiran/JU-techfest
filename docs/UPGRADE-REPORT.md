# ScamShield Security Platform Upgrade — Report

## 1. Root cause of the `loclx.io` misclassification

Reproduced with the shipped build:

```
$ scamshieldctl scan-url https://pjz22i41in.loclx.io
verdict: LOW RISK
risk:    0/100
```

The scan pipeline was structure-only and had no network access. `pjz22i41in.loclx.io`
contains no known brand token, no phishing keyword, no elevated-abuse TLD, no dangerous
file extension, no IP literal, no credentials and no suspicious port. Every heuristic
returned zero, the score clamped to `0`, and `RiskLevel.band(forScore: 0)` produced
`.low`.

The defect was not a missing rule for this URL. It was that **absence of evidence was
rendered as a low-risk verdict**. The engine did not model ephemeral relay
infrastructure, and it had no way to raise the verdict when the checks that would
establish safety had not run.

## 2. Engine changes

- `RiskLevel.inconclusive` added between `low` and `medium`. It requires an explicit
  bypass in the decision window, just like high/critical.
- `RelayInfrastructure.swift` recognises tunnelling providers (LocalXpose, ngrok,
  Cloudflare Quick Tunnel, localtunnel, Serveo, Pinggy, Microsoft Dev Tunnels, zrok,
  …), dynamic-DNS providers (DuckDNS, No-IP, FreeDNS, …), wildcard DNS (`sslip.io`,
  `nip.io`) and shared app hosting. Tunnel/dynamic endpoints add positive evidence
  (22/20/18); a machine-generated label adds 6. The parent service domain is not
  flagged, so `loclx.io` itself remains low risk. There is no domain-wide ban.
- Inconclusive is never auto-allowed. A relay host cannot be dragged back to `low` by
  repeated provider "clean" answers, because only one clean discount is ever applied.
- `CheckRecord` records each check as passed/failed/skipped/unavailable. `ScanResult`
  now carries `checks` and `evidenceSources` as optional fields, so old history still
  decodes.
- Every URL result lists what was not checked (reputation, page content, redirects)
  instead of silently folding those gaps into the score.

Verified after the change:

```
$ scamshieldctl scan-url https://pjz22i41in.loclx.io
verdict: CAUTION
risk:    28/100
evidence: [+22] Temporary relay endpoint (LocalXpose)
          [+ 6] Machine-generated relay hostname
```

## 3. New modules

| File | Purpose |
|---|---|
| `RelayInfrastructure.swift` | Tunnel / dynamic-DNS / shared-host detection and SSRF address classification |
| `SafeNetwork.swift` | SSRF-hardened outbound HTTP: scheme/port allowlists, DNS resolution checks, redirect re-validation, timeouts, 512 KB cap, no cookies/cache, TLS on |
| `ReputationService.swift` | VirusTotal, Google Safe Browsing, URLhaus; honest per-provider states; caching; no fabricated results |
| `PageInspector.swift` | HTML-only inspection: forms, password/payment fields, off-domain submits, brand claims, script patterns, trackers, meta-refresh |
| `InvestigationServices.swift` | Redirect tracing, security headers, email header analysis, brand comparison |
| `DomainInspector.swift` | Cloudflare DNS-over-HTTPS, RDAP registration/age, IP scope/reverse DNS/reputation |
| `AccountSecurity.swift` | Local password strength, HIBP breach lookup, k-anonymity Pwned Passwords |
| `FileInspector.swift` | Local signature/extension/hash inspection, optional VirusTotal hash lookup |
| `ScanMerger.swift` | Evidence-preserving merge of live checks, AI analysis that can only corroborate, and an optional explainer that cannot change verdicts |
| `ToolkitView.swift` | All 15 new sidebar tool UIs |
| `SecurityRegressionTests.swift` | 39 deterministic regression tests |

## 4. Sidebar tools implemented

**Protection:** Link & Message Scanner (extended with live re-check and AI explanation),
Website Safety Checker, QR/Screenshot scanning (Vision), Download Safety Checker.

**Investigation:** Domain Inspector, IP Reputation Checker, Redirect Tracker, Email
Header Analyzer, File Hash Checker, Security Headers Checker, Brand Impersonation
Checker.

**Account Security:** Breach Checker (HIBP), Password Checker (local strength +
k-anonymity breach check), Account Security Guide.

**Privacy:** Tracker Inspector, Permission & Privacy Audit, Incident Response Center.

**Workspace:** History & Reports (search/filter, JSON/CSV/Markdown export), Scam Lab,
Evaluation, Settings.

Each tool displays input validation, loading state, evidence, structured checks,
limitations and a recommended step. Buttons are connected to real analysis. Tools
requiring keys explain the requirement instead of returning a clean result.

## 5. Genuine integrations

- **VirusTotal v3** (URL, IP and file-hash lookups; handles 404/401/403/429/malformed).
- **Google Safe Browsing v4** `threatMatches:find`.
- **URLhaus abuse.ch** keyless feed (can be disabled).
- **Cloudflare DoH** and **RDAP** for DNS/registration data.
- **Have I Been Pwned** breach lookup (paid key required).
- **Pwned Passwords** k-anonymity range API (only 5 SHA-1 characters sent).
- **Optional OpenAI-compatible** AI explanation (evidence-only prompt; commentary
  cannot alter score/verdict).

Bounded live page inspection is on by default for manual scans and intercepted links;
it can be disabled in **Settings**. A separate setting waits for live checks before
showing the interception window rather than upgrading it in place. Missing key, error,
rate limit, timeout and unknown each have distinct states; none becomes "clean".

## 6. Security hardening

- Rejects loopback, private, link-local, CGNAT, multicast, reserved, documentation,
  IPv4-mapped IPv6, `*.local`, `*.internal`, `metadata.google.internal`.
- Validates scheme, port (80/443/8080/8443), resolves names before connecting, and
  re-validates every redirect (max 5).
- No TLS bypass, cookies, cache, credentials or form submission; no JavaScript
  execution; no file execution or upload.
- Response cap 512 KB; only the file hash (not the file) is sent to VirusTotal.
- API keys masked in UI, stored in the macOS login Keychain (never in settings.json), never logged.

## 7. Tests and measured results

```
swift test
Executed 69 tests, with 0 failures
```

- Existing suite: 30 tests (19 scanner/storage + 11 other core).
- New `SecurityRegressionTests`: 39 tests covering the `loclx.io` regression, benign
  relay parent and shared hosting, repeated clean discounts, unavailable providers,
  malicious matches, SSRF addresses/ports/schemes, typosquatting/homograph,
  embedded credentials, synthetic phishing and benign form fixtures, SHA-256/MD5
  correctness, password strength, k-anonymity prefix, risk vocabulary and tool
  validation.

Offline fixture evaluation (32 hand-written synthetic fixtures, no captured threat
feed):

```
fixtures: 32  detected: 32/32
precision: 1.00  recall: 1.00  f1: 1.00
false positives: 0  false negatives: 0
```

These figures describe the project's own labelled fixtures, not a general real-world
dataset. They are not evidence of production precision/recall.

Build:

```
swift build                       → Build complete
./scripts/build-app.sh            → Build complete, signature verifies
dist/ScamShield.app/.../scamshieldctl scan-url https://pjz22i41in.loclx.io
                                  → CAUTION, 28/100
```

## 8. Remaining limitations

- Live page inspection is on by default but reads HTML only; disabling live checks leaves a structural verdict that cannot see the page.
- JavaScript is not executed, so client-side rendering and post-load behaviour are not
  observed.
- PhishTank is not integrated (legacy key/approval requirement).
- HIBP breach lookup needs a paid key; without it the state is "skipped", not "clean".
- No certificate-transparency history, passive DNS or historical ownership lookup.
- AI commentary can be wrong; it never changes the verdict and is shown separately.
- No system-wide interception of in-app webviews is possible on macOS.
