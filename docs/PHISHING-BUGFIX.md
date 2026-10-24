# Phishing-page detection bug fix

## Reproduction (live)

```
$ scamshieldctl scan-url https://pjz22i41in.loclx.io --live
verdict: INCONCLUSIVE
risk:    28/100
checks:  Page content available — failed: HTTP 404
         Page fetch — HTTP 404, 2036 bytes
limit:   Page title: 404 TUNNEL NOT FOUND
```

DNS resolves to LocalXpose (`us.loclx.io`, 45.55.35.48), but the tunnel itself is
offline. The server returns a `404 TUNNEL NOT FOUND` page. The phishing content is not
available, so it is **not possible to detect the page live**. The result is now
INCONCLUSIVE rather than CAUTION-28-as-if-it-were-a-content-verdict. Evidence still
shows the relay endpoint, but no claim is made that the page was inspected.

Rechecked on 2026-10-24 during the AI/pre-click follow-up: the tunnel still returns
`404 TUNNEL NOT FOUND`; the live result remains INCONCLUSIVE 28/100.

## Why the old result was CAUTION 28

1. The default manual scan never ran live checks; it only used URL structure.
2. Relay infrastructure added 22 + 6 = 28, producing medium/caution.
3. The user's actual phishing page was never fetched, and the UI did not make that
   distinction prominent enough.
4. Even *with* live checks, the page was never inspected because live checks were off
   by default.

## Changes

- **Manual URL scans run the bounded live pipeline by default** (Settings can disable
  it). Intercepted links show the structural result immediately and are upgraded in
  place when the page scan completes. Waiting for live checks before opening the
  decision window remains a separate opt-in.
- **PageInspector.analyze(response:requestedURL:)** separates fetching from analysis, so
  the complete page logic is testable against deterministic local HTML fixtures.
- **Page-level phishing evidence** now includes:
  - unofficial brand claim in title/text, weighted strongly only when accompanied by a
    credential/payment form;
  - password/payment form detection with form destination and same-host vs off-domain
    distinction;
  - off-domain credential submission (forces high risk);
  - credential form + urgency/suspension/credential language combination;
  - brand impersonation + password form combination;
  - account-verification / password-reset wording on a password form;
  - multiple social-engineering themes without a form (caution, not high);
  - script-obfuscation patterns, meta refresh, tracker hosts, redirects.
- **False-positive controls**:
  - a same-host login form on an ordinary site is +6, not +24 (verified live against
    `github.com/login` → LOW 6/100);
  - a brand mention without a form is weak context, not impersonation;
  - a generic external search form is +6; only a credential/payment form posting
    off-domain is +22 and forces high;
  - pressure language without credential collection stays below high.
- **Merger semantics**:
  - URL, redirect, reputation and page evidence all feed one score;
  - a page that failed or returned 4xx/5xx is INCONCLUSIVE unless independent URL
    evidence is already high/critical;
  - skipped provider data never cancels page evidence;
  - sources list only providers actually contacted (not unconfigured ones);
  - the stale “Static analysis only” limitation is removed once a page was fetched.

## Verification

### Live

| Target | Result | Notes |
|---|---|---|
| `https://pjz22i41in.loclx.io` | INCONCLUSIVE 28/100 | DNS resolves; HTTP 404 TUNNEL NOT FOUND; page content unavailable |
| `https://github.com/login` | LOW 6/100 | Real login page, same-host form, no impersonation |
| `https://example.com` | LOW 0/100 | Page inspected, no suspicious content |
| `https://loclx.io` | INCONCLUSIVE | Does not resolve from this network; reported honestly |

### Local deterministic fixtures

| Fixture | Result |
|---|---|
| Fake PayPal login on `*.loclx.io`, off-domain credential POST, suspension/urgency text | **CRITICAL 100/100** — brand impersonation +26, off-domain credential form +22, password form +18, pressure combination +20, brand+form +18, reset pattern +8, text signals |
| Same phishing HTML on a non-relay host | HIGH or CRITICAL |
| Benign official PayPal login page | LOW |
| Ordinary same-host login page | LOW |
| Legitimate LocalXpose demo page, no credential form | not HIGH (relay caution only) |
| Suspicious language with no credential form | CAUTION, below HIGH |
| News article mentioning PayPal with no form | LOW (brand mention only) |
| Page fetch blocked by SSRF policy | INCONCLUSIVE, failed check recorded |
| HTTP 404 page | INCONCLUSIVE, failed check recorded |

The fixture result was also rendered through the real `ScanResultDetail` SwiftUI view
(`ScamShield --render-phishing-fixture <dir>`), showing CRITICAL with all page evidence
and passed page/form inspection checks.

## Tests / build

```
swift test   → 69 tests, 0 failures
swift build  → Build complete
./scripts/build-app.sh → Build complete, signature verifies
scamshieldctl selftest → PASS
fixture eval → 32/32, precision 1.00, recall 1.00 (synthetic project fixtures)
```
