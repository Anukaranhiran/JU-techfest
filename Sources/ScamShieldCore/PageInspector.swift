import Foundation

// MARK: - Website inspection
//
// The page is fetched as untrusted bytes through SafeFetcher. No script is executed,
// no form is submitted, no credentials are sent, and only the first 512 KB of the
// response is read. Everything below describes what is *visible in the markup*.
//
// Hidden-iframe and high-value-field heuristics are adapted from PhishLens (MIT,
// commit b85f7c6); see THIRD-PARTY-NOTICES.md for the licence and scope.

public struct InspectedForm: Codable, Sendable, Hashable, Identifiable {
    public var action: String
    public var method: String
    public var actionHost: String?
    /// True when the action's registrable domain differs from the page's. A form on
    /// `login.example.com` posting to `example.com` is same-site and is not flagged.
    public var actionIsExternal: Bool
    public var hasPasswordField: Bool
    public var hasEmailField: Bool
    public var hasPaymentField: Bool
    /// Non-payment high-value inputs such as SSN, OTP, PIN, seed phrase or recovery
    /// key. Payment card fields are reported separately by `hasPaymentField`.
    public var sensitiveFieldLabels: [String]
    public var fieldCount: Int
    public var id: String { action + "|" + method + "|" + String(fieldCount) }
}

/// A navigation target found in the landing page markup (an anchor, a button-like
/// element, a data attribute, a meta refresh or a statically recognisable JavaScript
/// navigation call). Discovery is static: page scripts are never executed.
public struct DiscoveredDestination: Codable, Sendable, Hashable, Identifiable {
    public enum Source: String, Codable, Sendable {
        case anchor
        case button
        case dataAttribute
        case metaRefresh
        case javascript
        case formAction
    }

    public var url: String
    public var host: String?
    public var label: String?
    public var source: Source
    /// Registrable domain differs from the page's registrable domain.
    public var isExternal: Bool
    /// Host belongs to a brand in ScamShield's official registry.
    public var isOfficialBrandHost: Bool

    public var id: String { url + "|" + source.rawValue + "|" + (label ?? "") }
}

/// The result of fetching and statically inspecting one discovered destination.
/// Fetches go through SafeFetcher, so the same SSRF, redirect, TLS, timeout and
/// response-size protections apply as to the landing page itself.
public struct DestinationInspection: Sendable {
    public var requestedURL: String
    public var finalURL: String?
    public var httpStatus: Int?
    public var title: String?
    public var contentAvailable: Bool
    public var bodyBytes: Int
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var hasPasswordForm: Bool
    public var hasPaymentForm: Bool
    public var hasBrandImpersonation: Bool
    public var hasCredentialExternalForm: Bool
}

public struct PageInspection: Sendable {
    public var requestedURL: String
    public var finalURL: String?
    public var httpStatus: Int?
    public var title: String?
    public var forms: [InspectedForm]
    public var scriptHosts: [String]
    public var trackerHosts: [String]
    public var iframeHosts: [String]
    public var imageHosts: [String]
    public var externalHosts: [String]
    public var suspiciousScriptPatterns: [String]
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var redirected: Bool
    public var truncated: Bool
    public var bodyBytes: Int
    /// A short, plain-text excerpt used only for the optional AI analysis. It is
    /// bounded and never includes raw markup, scripts or form submissions.
    public var textExcerpt: String
    /// Static navigation targets discovered in this page's markup.
    public var destinations: [DiscoveredDestination]
    /// Destinations that were fetched and inspected (bounded in number).
    public var destinationInspections: [DestinationInspection]

    public var hasPasswordForm: Bool { forms.contains { $0.hasPasswordField } }
    public var hasPaymentForm: Bool { forms.contains { $0.hasPaymentField } }
    public var hasExternalFormAction: Bool { forms.contains { $0.actionIsExternal } }
    /// A 200 status alone is insufficient: unsupported/empty bodies were not inspected.
    public var contentAvailable: Bool {
        (200..<300).contains(httpStatus ?? 0) && bodyBytes > 0
            && checks.contains { $0.name == "Form inspection" && $0.state == .passed }
    }
    /// An off-domain form that asks for a password or payment data. This is the
    /// subset of external forms strong enough to force a high-risk verdict.
    public var hasCredentialExternalForm: Bool {
        forms.contains { $0.actionIsExternal && ($0.hasPasswordField || $0.hasPaymentField) }
    }
    /// A fetched destination that actually presents a fake-login pattern. A page
    /// that merely links to Instagram is not included.
    public var hasDestinationCredentialHarvest: Bool {
        destinationInspections.contains {
            $0.contentAvailable && $0.hasPasswordForm
                && ($0.hasBrandImpersonation || $0.hasCredentialExternalForm)
        }
    }
}

public enum PageInspector {

    static let trackerDomains: Set<String> = [
        "google-analytics.com", "googletagmanager.com", "doubleclick.net", "facebook.net",
        "connect.facebook.net", "hotjar.com", "segment.io", "segment.com", "mixpanel.com",
        "amplitude.com", "fullstory.com", "clarity.ms", "tiktok.com", "analytics.tiktok.com",
        "twitter.com", "ads-twitter.com", "linkedin.com", "snap.licdn.com", "criteo.com",
        "taboola.com", "outbrain.com", "quantserve.com", "scorecardresearch.com",
        "newrelic.com", "sentry.io", "bugsnag.com", "intercom.io", "drift.com",
    ]

    /// Fetches a landing page, then a bounded number of external navigation
    /// destinations discovered in its markup. Each destination fetch uses SafeFetcher
    /// (SSRF + redirect revalidation + TLS + timeout + size cap). Forms are never
    /// submitted and scripts are never executed.
    public static func inspect(url: String, timeout: TimeInterval = 10,
                               maxDestinations: Int = 3) async -> PageInspection {
        let response: SafeHTTPResponse
        do {
            response = try await SafeFetcher.fetch(url, timeout: timeout, maxBytes: 512 * 1024)
        } catch {
            let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            let checks = [CheckRecord(name: "Page fetch", state: .failed, detail: detail)]
            return PageInspection(requestedURL: url, finalURL: nil, httpStatus: nil, title: nil,
                                  forms: [], scriptHosts: [], trackerHosts: [], iframeHosts: [],
                                  imageHosts: [], externalHosts: [], suspiciousScriptPatterns: [],
                                  evidence: [], checks: checks,
                                  limitations: ["The page could not be fetched: \(detail)", "An unreachable page is unknown, not safe."],
                                  redirected: false, truncated: false, bodyBytes: 0, textExcerpt: "",
                                  destinations: [], destinationInspections: [])
        }
        var inspection = analyze(response: response, requestedURL: url)
        guard inspection.contentAvailable else { return inspection }
        inspection.destinationInspections = await inspectDestinationPages(
            inspection.destinations, pageURL: inspection.finalURL ?? url,
            pageDomain: DomainUtils.registrableDomain((try? ParsedURL.parse(inspection.finalURL ?? url))?.host ?? ""),
            timeout: timeout, maxDestinations: maxDestinations)
        if !inspection.destinationInspections.isEmpty {
            let visited = inspection.destinationInspections
            let success = visited.filter(\.contentAvailable).count
            inspection.checks.append(CheckRecord(name: "Landing-page destinations",
                state: success > 0 ? .passed : .unavailable,
                detail: "Discovered \(inspection.destinations.count) navigation target(s); inspected \(visited.count), with \(success) available page(s)."))
            let unreachable = visited.filter { !$0.contentAvailable }
            if !unreachable.isEmpty {
                inspection.limitations.append("\(unreachable.count) discovered destination(s) could not be inspected; an unreachable destination is unknown, not safe.")
            }
            for destination in visited where destination.contentAvailable {
                inspection.limitations.append("Destination inspected: \(destination.finalURL ?? destination.requestedURL)")
            }
        } else if !inspection.destinations.filter(\.isExternal).isEmpty {
            inspection.checks.append(CheckRecord(name: "Landing-page destinations",
                state: .unavailable,
                detail: "External navigation targets were found but none could be safely inspected."))
            inspection.limitations.append("The page exposes external destinations, but they could not be inspected safely. Treat the destination as unverified.")
        }
        return inspection
    }

    static func inspectDestinationPages(_ destinations: [DiscoveredDestination],
                                       pageURL: String,
                                       pageDomain: String,
                                       timeout: TimeInterval,
                                       maxDestinations: Int) async -> [DestinationInspection] {
        // Only fetch destinations that are actually leaving the page's site. Same-site
        // anchors are ordinary navigation and are already represented by the page.
        let candidates = destinations.filter {
            $0.isExternal && $0.source != .formAction
                && !(URL(string: $0.url)?.host.map { DomainUtils.registrableDomain($0) == pageDomain } ?? false)
        }
        // Prefer buttons, JavaScript and meta refresh over ordinary anchors, then cap.
        let ordered = candidates.sorted { lhs, rhs in
            func priority(_ source: DiscoveredDestination.Source) -> Int {
                switch source {
                case .button, .dataAttribute: return 0
                case .metaRefresh, .javascript: return 1
                case .anchor: return 2
                case .formAction: return 3
                }
            }
            return priority(lhs.source) < priority(rhs.source)
        }
        var seenHosts: Set<String> = []
        var selected: [DiscoveredDestination] = []
        for candidate in ordered {
            let host = candidate.host ?? ""
            guard !seenHosts.contains(host) else { continue }
            seenHosts.insert(host)
            selected.append(candidate)
            if selected.count >= maxDestinations { break }
        }

        var results: [DestinationInspection] = []
        for destination in selected {
            do {
                let response = try await SafeFetcher.fetch(destination.url, timeout: timeout,
                                                           maxBytes: 512 * 1024)
                let nested = analyze(response: response, requestedURL: destination.url)
                results.append(DestinationInspection(
                    requestedURL: destination.url,
                    finalURL: response.finalURL,
                    httpStatus: response.status,
                    title: nested.title,
                    contentAvailable: nested.contentAvailable,
                    bodyBytes: nested.bodyBytes,
                    evidence: nested.evidence,
                    checks: nested.checks,
                    limitations: nested.limitations,
                    hasPasswordForm: nested.hasPasswordForm,
                    hasPaymentForm: nested.hasPaymentForm,
                    hasBrandImpersonation: nested.evidence.contains { $0.code == "page.brand-impersonation" || $0.code == "page.brand-credential-combo" },
                    hasCredentialExternalForm: nested.hasCredentialExternalForm))
            } catch {
                let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                results.append(DestinationInspection(
                    requestedURL: destination.url, finalURL: nil, httpStatus: nil, title: nil,
                    contentAvailable: false, bodyBytes: 0, evidence: [], checks: [
                        CheckRecord(name: "Destination fetch", state: .failed,
                                    detail: "\(destination.url): \(detail)"),
                    ], limitations: ["Destination \(destination.url) could not be fetched: \(detail)"],
                    hasPasswordForm: false, hasPaymentForm: false,
                    hasBrandImpersonation: false, hasCredentialExternalForm: false))
            }
        }
        return results
    }

    /// Pure analysis of an already-fetched response. Kept separate from `inspect(url:)`
    /// so the full page-phishing logic can be regression-tested against deterministic
    /// local fixtures without contacting any network endpoint.
    public static func analyze(response: SafeHTTPResponse, requestedURL: String) -> PageInspection {
        var evidence: [Evidence] = []
        var checks: [CheckRecord] = []
        var limitations: [String] = [
            "Only the HTML response was inspected. JavaScript was not executed, so content rendered client-side, pop-ups and credential capture after interaction are not visible.",
            "ScamShield does not submit forms and never sends credentials.",
        ]

        let contentType = response.contentType.lowercased()
        guard contentType.isEmpty || contentType.contains("html") || contentType.contains("text/plain") else {
            checks.append(CheckRecord(name: "Page content type", state: .failed,
                                      detail: "Server returned \(contentType); page markup was not inspected."))
            return PageInspection(requestedURL: requestedURL, finalURL: response.finalURL, httpStatus: response.status,
                                  title: nil, forms: [], scriptHosts: [], trackerHosts: [], iframeHosts: [],
                                  imageHosts: [], externalHosts: [], suspiciousScriptPatterns: [],
                                  evidence: [], checks: checks,
                                  limitations: ["The response is not HTML (\(contentType)). A file download was not opened.", "Unsupported content is unknown, not safe."],
                                  redirected: !response.redirects.isEmpty, truncated: response.truncated,
                                  bodyBytes: response.body.count, textExcerpt: "",
                                  destinations: [], destinationInspections: [])
        }

        let html = response.bodyText
        let parsed = try? ParsedURL.parse(response.finalURL)
        let pageHost = parsed?.host ?? URL(string: response.finalURL)?.host ?? ""
        let htmlLower = html.lowercased()

        func add(_ code: String, _ title: String, _ detail: String, _ weight: Int, _ category: Evidence.Category) {
            evidence.append(Evidence(code: code, title: title, detail: detail, weight: weight, category: category))
        }

        if !(200..<300).contains(response.status) || html.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            // An error page is not evidence of phishing and it is not evidence of
            // safety. It is an unavailable check, so it adds no risk weight; the
            // merger keeps the result at least inconclusive.
            add((200..<300).contains(response.status) ? "page.empty" : "page.http-error",
                (200..<300).contains(response.status) ? "Page returned an empty body" : "Page returned HTTP \(response.status)",
                "The requested page did not return a successful nonempty body. This is an unavailable check, not a clearance.",
                0, .content)
            checks.append(CheckRecord(name: "Page content available", state: .failed,
                                      detail: "HTTP \(response.status): the requested page did not return a successful nonempty body."))
            // Do not classify an error document as the requested page, even if an
            // error template contains brand names or an administrator login form.
            return PageInspection(requestedURL: requestedURL, finalURL: response.finalURL, httpStatus: response.status,
                title: firstMatch(in: html, pattern: #"(?is)<title[^>]*>(.*?)</title>"#).map(cleanText),
                forms: [], scriptHosts: [], trackerHosts: [], iframeHosts: [], imageHosts: [], externalHosts: [],
                suspiciousScriptPatterns: [], evidence: evidence, checks: checks,
                limitations: limitations + ["The requested page was unavailable or empty. No phishing or safety conclusion can be drawn from the error/empty response."],
                redirected: !response.redirects.isEmpty, truncated: response.truncated, bodyBytes: response.body.count,
                textExcerpt: String(cleanText(stripTags(html)).prefix(1_500)),
                destinations: [], destinationInspections: [])
        }
        if response.truncated {
            limitations.append("Only the first \(response.body.count / 1024) KB of the page was read; later markup was not inspected.")
        }
        if !response.redirects.isEmpty {
            let chain = response.redirects.map { "\($0.status) → \($0.to)" }.joined(separator: "; ")
            let changedHost = (try? ParsedURL.parse(response.requestedURL))?.host != pageHost
            add("page.redirected", changedHost ? "Redirected to a different host" : "Server-side redirect",
                "The server redirected before serving content: \(chain). The final destination is \(response.finalURL).",
                changedHost ? 16 : 8, .redirect)
        }

        let title = firstMatch(in: html, pattern: #"(?is)<title[^>]*>(.*?)</title>"#)
            .map(cleanText)?.nilIfEmpty
        if let title { limitations.append("Page title: \(title)") }

        let forms = extractForms(html: html, baseURL: response.finalURL, pageHost: pageHost)
        let scripts = extractHosts(html: html, pattern: #"(?is)<script[^>]+src\s*=\s*["']([^"']+)["']"#, baseURL: response.finalURL)
        let iframes = extractHosts(html: html, pattern: #"(?is)<iframe[^>]+src\s*=\s*["']([^"']+)["']"#, baseURL: response.finalURL)
        let images = extractHosts(html: html, pattern: #"(?is)<img[^>]+src\s*=\s*["']([^"']+)["']"#, baseURL: response.finalURL)
        let allExternal = Array(Set(scripts + iframes + images + forms.compactMap { $0.actionIsExternal ? $0.actionHost : nil })).sorted()
        let destinations = extractDestinations(html: html, baseURL: response.finalURL, pageHost: pageHost)

        let trackers = Array(Set(scripts + iframes + images)).filter { host in
            let registrable = DomainUtils.registrableDomain(host)
            return trackerDomains.contains(registrable) || trackerDomains.contains(where: { host.hasSuffix($0) })
        }.sorted()

        if !trackers.isEmpty {
            add("page.trackers", "\(trackers.count) tracker domain(s) referenced",
                "Third-party analytics/advertising hosts referenced by the page: \(trackers.prefix(4).joined(separator: ", ")). This is a privacy observation, not proof of malice.",
                min(4 + trackers.count, 10), .content)
        }
        if iframes.count >= 3 {
            add("page.many-iframes", "Several embedded frames",
                "The page embeds \(iframes.count) external frames, which can hide a credential form inside an otherwise ordinary page.",
                8, .content)
        }
        let hiddenIframes = hiddenIframeCount(in: html)
        if hiddenIframes > 0 {
            add("page.hidden-iframes", "Hidden embedded frame(s)",
                "The markup contains \(hiddenIframes) iframe(s) hidden with zero size, display:none, visibility:hidden or the hidden attribute. Invisible frames are used for clickjacking and silent redirects.",
                10, .content)
        }

        // Forms. A login form on the same host is ordinary and gets only a small
        // weight; it becomes evidence when the destination differs or the page is
        // impersonating a brand (the combination block below handles the latter).
        if let form = forms.first(where: { $0.hasPasswordField }) {
            let official = parsed.map { BrandRegistry.officialBrand(forHost: $0.host) != nil } ?? false
            let action = form.actionHost ?? "an unparseable destination"
            let weight = official ? 3 : (form.actionIsExternal ? 18 : 6)
            add("page.password-form", "Password field submits to \(action)",
                "A login form on \(pageHost) posts \(form.fieldCount) field(s) to \(form.action). ScamShield did not submit it.\(official ? " The host is an official brand domain, but still verify the address before typing." : (form.actionIsExternal ? " The destination is a different domain than the page you are looking at." : ""))",
                weight, .content)
        }
        if forms.contains(where: { $0.hasPaymentField }) {
            add("page.payment-form", "Payment card fields on the page",
                "The page contains card-number/CVV/expiry inputs. Never enter card data on a site you reached from an unsolicited message.",
                18, .content)
        }
        let sensitiveLabels = Array(Set(forms.flatMap(\.sensitiveFieldLabels))).sorted()
        if !sensitiveLabels.isEmpty {
            let officialHost = parsed.map { BrandRegistry.officialBrand(forHost: $0.host) != nil } ?? false
            add("page.high-value-fields", "Page asks for high-value identity or authentication data",
                "The page contains input fields for \(sensitiveLabels.prefix(4).joined(separator: ", ")). Requests for SSNs, one-time codes, PINs or wallet recovery phrases are the final step of many phishing and account-takeover attacks.",
                officialHost ? 2 : 14, .content)
        }
        if let form = forms.first(where: { $0.actionIsExternal && ($0.hasPasswordField || $0.hasPaymentField) })
            ?? forms.first(where: { $0.actionIsExternal }) {
            let collectsSecret = form.hasPasswordField || form.hasPaymentField
            add("page.external-form", collectsSecret ? "Credential form submits to a different domain" : "Form submits to a different domain",
                "A form posts to \(form.actionHost ?? form.action), not \(pageHost).\(collectsSecret ? " Credentials entered here would go to a different operator." : " This may be an ordinary search or newsletter integration; no password or payment field was found in that form.")",
                collectsSecret ? 22 : 6, .content)
        }

        // Suspicious inline script patterns. High false-positive risk, so low weight.
        let scriptPatterns: [(String, String)] = [
            ("eval(", "eval()"), ("document.write", "document.write"), ("atob(", "atob() base64 decoding"),
            ("unescape(", "unescape()"), ("string.fromcharcode", "String.fromCharCode"),
            ("crypto", "crypto wallet access"), ("clipboard", "clipboard access"),
        ]
        var foundScripts: [String] = []
        for (needle, label) in scriptPatterns where htmlLower.contains(needle) {
            foundScripts.append(label)
        }
        if foundScripts.count >= 2 {
            add("page.script-patterns", "Obfuscation-style script patterns",
                "The markup contains \(foundScripts.joined(separator: ", ")). These appear in legitimate sites too, but are common in phishing kits.",
                min(foundScripts.count * 4, 16), .content)
        }

        // Visible text + social engineering.
        let visible = cleanText(stripTags(html))
        let textResult = TextAnalyzer.analyze(String(visible.prefix(20_000)))
        for item in textResult.evidence where item.weight > 0 {
            // Message rules such as "enter your password" are normal instructions
            // on a login page, not independent proof of credential theft.
            if forms.contains(where: { $0.hasPasswordField }),
               ["text.otp", "text.credentials"].contains(item.code) { continue }
            evidence.append(Evidence(code: "page." + item.code, title: "Page text: " + item.title,
                                     detail: item.detail, weight: Int(Double(item.weight) * 0.7), category: .content))
        }

        // Brand impersonation in the page's title/text versus the host. A passing
        // brand mention (news article, review, documentation) is common and must not
        // be treated like a fake login. Require credential collection for the strong
        // claim and prefer the title's brand over incidental body mentions.
        let pageText = String(visible.prefix(4_000)).lowercased()
        let titleText = (title ?? "").lowercased()
        let hasCredentialForm = forms.contains { $0.hasPasswordField }
        let hasPaymentForm = forms.contains { $0.hasPaymentField }
        var claimedBrand: Brand?
        func mentions(_ brand: Brand, in text: String) -> Bool {
            brand.tokens.contains { text.range(of: "\\b" + NSRegularExpression.escapedPattern(for: $0) + "\\b", options: .regularExpression) != nil }
        }
        let prominentBrand = BrandRegistry.brands.first { mentions($0, in: titleText) }
            ?? BrandRegistry.brands.first { mentions($0, in: pageText) }
        if let parsed,
           let brand = prominentBrand,
           !BrandRegistry.isOfficial(host: parsed.host, for: brand) {
            if hasCredentialForm || hasPaymentForm {
                claimedBrand = brand
                add("page.brand-impersonation", "Page claims \(brand.name) on an unofficial host",
                    "The page names \(brand.name) but is served from \(parsed.registrableDomain), not \(brand.domains[0]). A credential or payment form on an unofficial brand page is the central phishing signal.",
                    26, .brand)
            } else {
                add("page.brand-mention", "Unofficial page mentions \(brand.name)",
                    "The page text mentions \(brand.name) but does not present a login or payment form for it. A brand mention alone is weak context, not proof of impersonation.",
                    6, .brand)
            }
        }

        // Combination evidence. Credential collection is common on the real web, and
        // pressure language is common in marketing; the two together on an unofficial
        // host is the phishing script. These add to, rather than replace, the
        // individual findings above.
        let pressurePattern = #"(?i)\b(?:urgent(?:ly)?|immediately|final notice|last warning|within (?:24|48) hours)\b|\baccount\b.{0,60}\b(?:suspend\w*|locked|deactivat\w*|closed)\b"#
        if hasCredentialForm, visible.range(of: pressurePattern, options: .regularExpression) != nil {
            add("page.credential-pressure-combo", "Credential form combined with pressure language",
                "This page asks for a password while using urgency, suspension threats or credential requests. Legitimate login pages do not need to scare you into signing in.",
                20, .content)
        }
        if hasCredentialForm, claimedBrand != nil {
            add("page.brand-credential-combo", "Brand impersonation plus a password form",
                "The page claims a brand it is not hosted on and collects a password. Taken together this is a fake-login pattern, not an accidental mention.",
                18, .brand)
        }
        let resetWords = ["reset", "verify", "verification", "unlock", "confirm", "suspended", "limited", "unusual activity"]
        if hasCredentialForm, resetWords.contains(where: { titleText.contains($0) || pageText.contains($0) }) {
            add("page.reset-form-pattern", "Account-verification / password-reset form",
                "A password field appears under account-verification or reset wording. Phishing kits reproduce this exact flow to capture the old password and any second factor.",
                8, .content)
        }
        // Pressure language without any credential form is still worth a caution, but
        // deliberately stays below the high-risk band: marketing and support pages
        // use urgent wording too.
        if !hasCredentialForm, textResult.matchedRules.count >= 2 {
            add("page.social-engineering", "Multiple social-engineering themes without a form",
                "The page combines \(textResult.matchedRules.count) pressure or threat themes but has no credential fields in its HTML. That is suspicious context, not proof of credential theft.",
                14, .content)
        }

        // Meta refresh / immediate navigation hides the destination.
        if let refresh = firstMatch(in: html, pattern: #"(?is)<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*>"#),
           refresh.lowercased().contains("url=") {
            let target = destinations.first(where: { $0.source == .metaRefresh })?.url
            add("page.meta-refresh", "Page forwards somewhere else immediately",
                "A meta refresh redirects the browser after load\(target.map { " to \($0)" } ?? ""). The destination shown in the address bar is not where the user ends up.",
                14, .redirect)
        }

        // Landing-page navigation. A Visit button, a JavaScript navigation or a
        // concealed data attribute can hide the real destination from the address
        // bar. We report the destination and analyse its URL statically here; the
        // async inspector later fetches a bounded number of them.
        let externalDestinations = destinations.filter(\.isExternal)
        if !externalDestinations.isEmpty {
            let actionWords = ["visit", "continue", "proceed", "open", "claim", "verify", "confirm", "sign in", "log in", "connect", "join", "start"]
            for destination in externalDestinations.prefix(8) {
                guard let parsedDestination = try? ParsedURL.parse(destination.url),
                      parsedDestination.isWebScheme else { continue }
                let official = BrandRegistry.officialBrand(forHost: parsedDestination.host) != nil
                let labelText = (destination.label ?? "").lowercased()
                let labelBrand = BrandRegistry.brands.first { brand in
                    brand.tokens.contains { labelText.range(of: "\\b" + NSRegularExpression.escapedPattern(for: $0) + "\\b", options: .regularExpression) != nil }
                }
                let labelMentionsAction = actionWords.contains { labelText.contains($0) }
                let buttonLike = destination.source == .button || destination.source == .dataAttribute
                    || (destination.source == .anchor && labelMentionsAction)

                if let labelBrand, !BrandRegistry.isOfficial(host: parsedDestination.host, for: labelBrand) {
                    add("page.misleading-visit-label", "“\(destination.label ?? "Link")” leads to \(parsedDestination.host)",
                        "The visible label names \(labelBrand.name), but the destination is \(parsedDestination.registrableDomain), not \(labelBrand.domains[0]). The button text and the real destination disagree.",
                        22, .redirect)
                } else if let brand = claimedBrand, !BrandRegistry.isOfficial(host: parsedDestination.host, for: brand), !official {
                    add("page.brand-misdirected-visit", "\(brand.name) page sends visitors to \(parsedDestination.host)",
                        "The page presents itself as \(brand.name) but its navigation leads to \(parsedDestination.registrableDomain). That is not the brand's official domain.",
                        20, .brand)
                } else if destination.source == .javascript || destination.source == .metaRefresh {
                    add("page.concealed-navigation", "Navigation destination hidden in page code",
                        "The page changes location to \(parsedDestination.host) through \(destination.source == .javascript ? "JavaScript" : "a meta refresh"). That destination is not visible as an ordinary link.",
                        12, .redirect)
                } else if buttonLike, !official, !labelMentionsAction, destination.source != .anchor {
                    add("page.visit-button-external", "Button opens an external site",
                        "A button leads to \(parsedDestination.registrableDomain), which is outside the page's own domain. This is not malicious by itself; it becomes relevant when the page claims a different identity.",
                        6, .redirect)
                }

                // Fold the strongest static URL evidence about the destination. This
                // catches a Visit button pointing at a look-alike/login URL even when
                // that destination cannot be fetched.
                let staticEvidence = URLAnalyzer.analyze(parsedDestination)
                    .filter { $0.weight > 0 }
                    .sorted { $0.weight > $1.weight }
                    .prefix(2)
                for item in staticEvidence {
                    evidence.append(Evidence(code: "page.destination." + item.code,
                        title: "Navigation destination: " + item.title,
                        detail: "The page points to \(parsedDestination.normalized). \(item.detail)",
                        weight: max(1, Int(Double(item.weight) * 0.7)), category: item.category))
                }
            }
        }

        checks.append(CheckRecord(name: "Page fetch", state: .passed,
                                  detail: "HTTP \(response.status), \(response.body.count) bytes, \(response.elapsedMs.rounded()) ms."))
        checks.append(CheckRecord(name: "Form inspection", state: .passed,
                                  detail: "\(forms.count) form(s); password: \(forms.contains { $0.hasPasswordField }); payment: \(forms.contains { $0.hasPaymentField }); high-value fields: \(sensitiveLabels.count); hidden iframes: \(hiddenIframes)."))
        checks.append(CheckRecord(name: "Script execution", state: .skipped,
                                  detail: "JavaScript was deliberately not executed. Dynamic content is unseen."))
        checks.append(CheckRecord(name: "Third-party requests", state: .passed,
                                  detail: "\(allExternal.count) referenced external host(s) read from markup; no request was made to them except the page itself."))
        if response.status >= 400 {
            checks.append(CheckRecord(name: "Trustworthy content", state: .failed,
                                      detail: "The server returned an error page, so content-based clearance is impossible."))
        }

        return PageInspection(
            requestedURL: requestedURL,
            finalURL: response.finalURL,
            httpStatus: response.status,
            title: title,
            forms: forms,
            scriptHosts: scripts,
            trackerHosts: trackers,
            iframeHosts: iframes,
            imageHosts: images,
            externalHosts: allExternal,
            suspiciousScriptPatterns: foundScripts,
            evidence: evidence,
            checks: checks,
            limitations: limitations,
            redirected: !response.redirects.isEmpty,
            truncated: response.truncated,
            bodyBytes: response.body.count,
            textExcerpt: String(visible.prefix(1_500)),
            destinations: destinations, destinationInspections: [])
    }

    // MARK: Markup helpers

    /// Discovers navigation targets without executing page scripts. The extractor is
    /// deliberately conservative: it records only explicit URLs, not every string in
    /// inline JavaScript.
    static func extractDestinations(html: String, baseURL: String, pageHost: String) -> [DiscoveredDestination] {
        let pageDomain = DomainUtils.registrableDomain(pageHost)
        var found: [DiscoveredDestination] = []
        var seen: Set<String> = []

        func append(_ raw: String, label: String?, source: DiscoveredDestination.Source) {
            let cleaned = cleanText(raw)
            guard !cleaned.isEmpty else { return }
            let lower = cleaned.lowercased()
            guard !lower.hasPrefix("javascript:"), !lower.hasPrefix("mailto:"),
                  !lower.hasPrefix("tel:"), !lower.hasPrefix("data:"),
                  !lower.hasPrefix("#") else { return }
            if lower.hasPrefix("http://") == false,
               lower.hasPrefix("https://") == false,
               lower.hasPrefix("//") == false,
               lower.hasPrefix("/") == false,
               lower.hasPrefix("./") == false,
               lower.hasPrefix("../") == false {
                return
            }
            guard let resolved = resolve(cleaned, base: baseURL),
                  let parsed = try? ParsedURL.parse(resolved),
                  parsed.isWebScheme else { return }
            let key = parsed.normalized
            guard !seen.contains(key) else { return }
            seen.insert(key)
            found.append(DiscoveredDestination(
                url: parsed.normalized,
                host: parsed.host,
                label: label.map { String($0.prefix(120)) },
                source: source,
                isExternal: DomainUtils.registrableDomain(parsed.host) != pageDomain,
                isOfficialBrandHost: BrandRegistry.officialBrand(forHost: parsed.host) != nil))
        }

        func matches(_ pattern: String, in text: String) -> [(NSTextCheckingResult, NSString)] {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
            let ns = text as NSString
            return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ($0, ns) }
        }

        // Anchors, including role="button" links and links whose destination is in a
        // data attribute.
        for (match, ns) in matches(#"(?is)<a\b([^>]*)>(.*?)</a>"#, in: html) {
            guard match.numberOfRanges >= 3 else { continue }
            let opening = ns.substring(with: match.range(at: 1))
            let label = cleanText(stripTags(ns.substring(with: match.range(at: 2))))
            let raw = attribute("href", in: opening)
                ?? attribute("data-href", in: opening)
                ?? attribute("data-url", in: opening)
                ?? attribute("data-link", in: opening)
                ?? attribute("data-destination", in: opening)
                ?? attribute("data-redirect", in: opening)
            if let raw {
                append(raw, label: label.nilIfEmpty, source: .anchor)
            }
            if let js = attribute("onclick", in: opening) {
                for destination in javascriptDestinations(in: js) {
                    append(destination, label: label.nilIfEmpty, source: .javascript)
                }
            }
        }

        // Buttons and elements with an explicit navigation data attribute. A plain
        // <button> with no URL is not a destination; the form parser handles actions.
        for (match, ns) in matches(#"(?is)<button\b([^>]*)>(.*?)</button>"#, in: html) {
            guard match.numberOfRanges >= 3 else { continue }
            let opening = ns.substring(with: match.range(at: 1))
            let label = cleanText(stripTags(ns.substring(with: match.range(at: 2))))
            let raw = attribute("data-href", in: opening)
                ?? attribute("data-url", in: opening)
                ?? attribute("data-link", in: opening)
                ?? attribute("data-destination", in: opening)
                ?? attribute("data-redirect", in: opening)
                ?? attribute("formaction", in: opening)
            if let raw {
                append(raw, label: label.nilIfEmpty, source: .button)
            }
            if let js = attribute("onclick", in: opening) {
                for destination in javascriptDestinations(in: js) {
                    append(destination, label: label.nilIfEmpty, source: .javascript)
                }
            }
        }

        // Any element carrying a navigation data attribute.
        for (match, ns) in matches(#"(?is)<[a-z][a-z0-9]*\b([^>]*\bdata-(?:href|url|link|destination|redirect)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)[^>]*)>"#, in: html) {
            guard match.numberOfRanges >= 2 else { continue }
            let opening = ns.substring(with: match.range(at: 1))
            let raw = attribute("data-href", in: opening)
                ?? attribute("data-url", in: opening)
                ?? attribute("data-link", in: opening)
                ?? attribute("data-destination", in: opening)
                ?? attribute("data-redirect", in: opening)
            if let raw { append(raw, label: nil, source: .dataAttribute) }
        }

        // Meta refresh.
        for (match, ns) in matches(#"(?is)<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>"#, in: html) {
            let tag = ns.substring(with: match.range)
            guard let content = attribute("content", in: tag) else { continue }
            if let range = content.range(of: #"(?i)url\s*=\s*(.+)$"#, options: .regularExpression) {
                let raw = String(content[range]).replacingOccurrences(of: #"(?i)^url\s*=\s*"#, with: "", options: .regularExpression)
                append(raw.trimmingCharacters(in: CharacterSet(charactersIn: " \"'")), label: nil, source: .metaRefresh)
            }
        }

        // Static JavaScript navigation. This does not execute anything; it merely
        // reads literal strings passed to location.assign/replace, location.href and
        // window.open. Computed destinations are reported as undiscoverable by the
        // page limitation.
        for pattern in [
            #"(?is)(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"#,
            #"(?is)(?:window\.|document\.|top\.|self\.)?location\.(?:assign|replace)\s*\(\s*["']([^"']+)["']"#,
            #"(?is)window\.open\s*\(\s*["']([^"']+)["']"#,
        ] {
            for (match, ns) in matches(pattern, in: html) where match.numberOfRanges >= 2 {
                append(ns.substring(with: match.range(at: 1)), label: nil, source: .javascript)
            }
        }

        return found
    }

    /// Literal URLs passed to common navigation functions inside an inline handler or
    /// script. Deliberately small and literal; no JavaScript is executed.
    static func javascriptDestinations(in code: String) -> [String] {
        var urls: [String] = []
        for pattern in [
            #"(?is)(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"#,
            #"(?is)(?:window\.|document\.|top\.|self\.)?location\.(?:assign|replace)\s*\(\s*["']([^"']+)["']"#,
            #"(?is)window\.open\s*\(\s*["']([^"']+)["']"#,
        ] {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            let ns = code as NSString
            for match in regex.matches(in: code, range: NSRange(location: 0, length: ns.length))
            where match.numberOfRanges >= 2 {
                urls.append(ns.substring(with: match.range(at: 1)))
            }
        }
        return urls
    }

    /// Counts iframes hidden by inline style, zero width/height or the hidden
    /// attribute. Adapted from the hidden-iframe heuristic in PhishLens (MIT).
    static func hiddenIframeCount(in html: String) -> Int {
        guard let regex = try? NSRegularExpression(pattern: #"(?is)<iframe\b[^>]*>"#) else { return 0 }
        let ns = html as NSString
        var count = 0
        for match in regex.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
            let tag = ns.substring(with: match.range).lowercased()
            let style = attribute("style", in: tag)?.lowercased() ?? ""
            let width = attribute("width", in: tag)?.trimmingCharacters(in: .whitespaces) ?? ""
            let height = attribute("height", in: tag)?.trimmingCharacters(in: .whitespaces) ?? ""
            let zeroSize = ["0", "1", "0px", "1px"].contains(width)
                && ["0", "1", "0px", "1px"].contains(height)
            let hiddenStyle = style.contains("display:none") || style.contains("display: none")
                || style.contains("visibility:hidden") || style.contains("visibility: hidden")
            let hiddenAttribute = tag.range(of: #"\shidden(?:\s|=|>)"#,
                                            options: .regularExpression) != nil
            if zeroSize || hiddenStyle || hiddenAttribute { count += 1 }
        }
        return count
    }

    static func extractForms(html: String, baseURL: String, pageHost: String) -> [InspectedForm] {
        guard let regex = try? NSRegularExpression(pattern: #"(?is)<form\b[^>]*>(.*?)</form>"#) else { return [] }
        let html = html.replacingOccurrences(of: #"(?is)<!--.*?-->|<(script|style|template)\b[^>]*>.*?</\1\s*>"#, with: "", options: .regularExpression)
        let ns = html as NSString
        var forms: [InspectedForm] = []
        for match in regex.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
            guard match.numberOfRanges >= 2 else { continue }
            let full = ns.substring(with: match.range)
            let inner = ns.substring(with: match.range(at: 1))
            let opening = String(full.prefix { $0 != ">" })
            let actionRaw = attribute("action", in: opening) ?? ""
            let method = (attribute("method", in: opening) ?? "get").lowercased()
            let resolved = actionRaw.isEmpty ? baseURL : resolve(actionRaw, base: baseURL)
            let actionHost = resolved.flatMap { URL(string: $0)?.host }
            let external = actionHost.map {
                DomainUtils.registrableDomain($0) != DomainUtils.registrableDomain(pageHost)
            } ?? false
            let inputs = (try? NSRegularExpression(pattern: #"(?is)<input\b[^>]*>"#))?
                .matches(in: inner, range: NSRange(inner.startIndex..., in: inner))
                .map { (inner as NSString).substring(with: $0.range) } ?? []
            let descriptors = inputs.map { input in
                ["name", "id", "autocomplete", "placeholder"].compactMap { attribute($0, in: input) }.joined(separator: " ").lowercased()
            }
            let sensitive = descriptors.compactMap { descriptor -> String? in
                let rules: [(String, String)] = [
                    ("ssn", "SSN"), ("social security", "SSN"), ("social-security", "SSN"),
                    ("one-time", "one-time code"), ("one_time", "one-time code"),
                    ("otp", "one-time code"), ("2fa", "one-time code"),
                    ("verification code", "one-time code"), ("authenticator", "one-time code"),
                    ("seed phrase", "seed phrase"), ("seed-phrase", "seed phrase"),
                    ("recovery phrase", "recovery phrase"), ("recovery-phrase", "recovery phrase"),
                    ("private key", "private key"), ("private-key", "private key"),
                    ("passphrase", "wallet passphrase"), ("pin", "PIN"),
                ]
                return rules.first { descriptor.contains($0.0) }?.1
            }
            forms.append(InspectedForm(
                action: resolved ?? actionRaw,
                method: method,
                actionHost: actionHost,
                actionIsExternal: external,
                hasPasswordField: inputs.contains { attribute("type", in: $0)?.lowercased() == "password" },
                hasEmailField: inputs.contains { attribute("type", in: $0)?.lowercased() == "email" || attribute("name", in: $0)?.lowercased() == "email" },
                hasPaymentField: descriptors.contains { value in ["card", "cvv", "cvc", "expiry", "creditcard", "cardnumber", "cc-number"].contains { value.contains($0) } },
                sensitiveFieldLabels: Array(Set(sensitive)).sorted(),
                fieldCount: fieldCount(in: inner)))
        }
        return forms
    }

    static func fieldCount(in html: String) -> Int {
        guard let regex = try? NSRegularExpression(pattern: #"(?is)<(input|select|textarea)\b"#) else { return 0 }
        return regex.numberOfMatches(in: html, range: NSRange(location: 0, length: (html as NSString).length))
    }

    static func attribute(_ name: String, in tag: String) -> String? {
        let pattern = "(?is)(?:^|\\s)" + NSRegularExpression.escapedPattern(for: name) + #"\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: tag, range: NSRange(tag.startIndex..., in: tag)) else { return nil }
        for index in 1..<match.numberOfRanges where match.range(at: index).location != NSNotFound {
            return cleanText((tag as NSString).substring(with: match.range(at: index)))
        }
        return nil
    }

    static func resolve(_ value: String, base: String) -> String? {
        guard !value.isEmpty, !value.lowercased().hasPrefix("javascript:") else { return nil }
        if value.lowercased().hasPrefix("http://") || value.lowercased().hasPrefix("https://") { return value }
        return URL(string: value, relativeTo: URL(string: base))?.absoluteString
    }

    static func extractHosts(html: String, pattern: String, baseURL: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = html as NSString
        var hosts: [String] = []
        for match in regex.matches(in: html, range: NSRange(location: 0, length: ns.length)) where match.numberOfRanges >= 2 {
            let raw = ns.substring(with: match.range(at: 1))
            guard let resolved = resolve(raw, base: baseURL), let host = URL(string: resolved)?.host else { continue }
            let normalized = DomainUtils.normalizeHost(host)
            if !normalized.isEmpty, !hosts.contains(normalized) { hosts.append(normalized) }
        }
        return hosts
    }

    static func firstMatch(in text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = text as NSString
        guard let match = regex.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              match.numberOfRanges >= 2 else { return nil }
        return ns.substring(with: match.range(at: 1))
    }

    static func stripTags(_ html: String) -> String {
        var text = html
        for pattern in [#"(?is)<script[^>]*>.*?</script>"#, #"(?is)<style[^>]*>.*?</style>"#, #"(?is)<[^>]+>"#] {
            text = text.replacingOccurrences(of: pattern, with: " ", options: .regularExpression)
        }
        return text
    }

    static func cleanText(_ text: String) -> String {
        var value = text
            .replacingOccurrences(of: "&nbsp;", with: " ")
            .replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&#39;", with: "'")
        value = value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
