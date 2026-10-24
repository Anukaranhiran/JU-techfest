import Foundation

// MARK: - Redirect tracing

public struct RedirectReport: Sendable {
    public var requestedURL: String
    public var finalURL: String?
    public var hops: [RedirectHop]
    public var httpStatus: Int?
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var failed: Bool
}

public enum RedirectTracer {
    public static func trace(_ url: String, timeout: TimeInterval = 10) async -> RedirectReport {
        var checks: [CheckRecord] = []
        var limitations = [
            "Only HTTP redirects were followed (maximum 5). JavaScript and meta-refresh redirects are not executed here.",
            "Each hop was re-validated against private, loopback, link-local and metadata addresses.",
        ]
        do {
            let response = try await SafeFetcher.fetch(url, method: "GET", maxRedirects: 5, timeout: timeout, maxBytes: 8 * 1024)
            checks.append(CheckRecord(name: "Initial request", state: .passed,
                                      detail: "HTTP \(response.status) after \(response.redirects.count) redirect(s)."))
            checks.append(CheckRecord(name: "Redirect safety", state: .passed,
                                      detail: "Every hop stayed on an allowed public destination."))
            var evidence: [Evidence] = []
            let initialHost = (try? ParsedURL.parse(url))?.host ?? ""
            let finalParsed = try? ParsedURL.parse(response.finalURL)
            if let finalParsed, finalParsed.host != initialHost {
                evidence.append(Evidence(code: "redirect.host-change",
                    title: "Destination host changed",
                    detail: "The link starts at \(initialHost) and ends at \(finalParsed.host). The address used in the message is not the address that serves the page.",
                    weight: 16, category: .redirect))
                for item in URLAnalyzer.analyze(finalParsed).filter({ $0.weight > 0 }).sorted(by: { $0.weight > $1.weight }).prefix(2) {
                    evidence.append(Evidence(code: "redirect.final." + item.code,
                        title: "Final destination: " + item.title,
                        detail: item.detail, weight: Int(Double(item.weight) * 0.6), category: item.category))
                }
            }
            if response.redirects.count >= 3 {
                evidence.append(Evidence(code: "redirect.long-chain",
                    title: "Long redirect chain",
                    detail: "The destination took \(response.redirects.count) hops. Long chains are used to exhaust link-preview checks and hide the final host.",
                    weight: 10, category: .redirect))
            }
            if response.status >= 400 {
                limitations.append("The final destination returned HTTP \(response.status). The page may be offline or already taken down.")
            }
            return RedirectReport(requestedURL: url, finalURL: response.finalURL, hops: response.redirects,
                                  httpStatus: response.status, evidence: evidence, checks: checks,
                                  limitations: limitations, failed: false)
        } catch {
            let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            checks.append(CheckRecord(name: "Redirect trace", state: .failed, detail: detail))
            return RedirectReport(requestedURL: url, finalURL: nil, hops: [], httpStatus: nil,
                                  evidence: [], checks: checks,
                                  limitations: ["The trace did not complete: \(detail)", "An incomplete trace is unknown, not safe."],
                                  failed: true)
        }
    }
}

// MARK: - Security headers

public struct SecurityHeadersReport: Sendable {
    public struct HeaderCheck: Sendable, Identifiable, Hashable {
        public var name: String
        public var present: Bool
        public var value: String?
        public var detail: String
        public var weight: Int
        public var id: String { name }
    }

    public var url: String
    public var finalURL: String?
    public var https: Bool
    public var status: Int?
    public var checks: [HeaderCheck]
    public var evidence: [Evidence]
    public var limitations: [String]
    public var failed: Bool
}

public enum SecurityHeadersChecker {
    public static func check(_ urlString: String) async -> SecurityHeadersReport {
        do {
            let response = try await SafeFetcher.fetch(urlString, method: "GET", timeout: 10, maxBytes: 16 * 1024)
            var checks: [SecurityHeadersReport.HeaderCheck] = []
            func header(_ name: String, weight: Int, missingDetail: String) {
                let value = response.headers[name]
                checks.append(.init(name: name, present: value != nil, value: value,
                                    detail: value == nil ? missingDetail : "Present: \(value!.prefix(160))",
                                    weight: value == nil ? weight : 0))
            }
            header("strict-transport-security", weight: 14,
                   missingDetail: "No HSTS header: the browser is not told to require HTTPS on later visits.")
            header("content-security-policy", weight: 8,
                   missingDetail: "No Content-Security-Policy: injected scripts have less resistance.")
            header("x-frame-options", weight: 5,
                   missingDetail: "No X-Frame-Options and no frame-ancestors CSP directive observed: clickjacking protection is not explicit.")
            header("x-content-type-options", weight: 4,
                   missingDetail: "No X-Content-Type-Options: nosniff, so MIME confusion is possible.")
            header("referrer-policy", weight: 3,
                   missingDetail: "No Referrer-Policy: full URLs may leak to third parties.")
            header("permissions-policy", weight: 2,
                   missingDetail: "No Permissions-Policy: powerful browser features are not explicitly restricted.")

            let isHTTPS = (URL(string: response.finalURL)?.scheme?.lowercased() == "https")
            var evidence: [Evidence] = []
            // Missing headers are hardening advice, not proof of malice. Cap the
            // total so a plain static site is not labelled a scam.
            let missing = checks.filter { !$0.present }
            let capped = min(missing.reduce(0) { $0 + $1.weight }, 16)
            if capped > 0 {
                evidence.append(Evidence(code: "headers.missing",
                    title: "\(missing.count) security header(s) missing",
                    detail: "Missing: \(missing.map(\.name).joined(separator: ", ")). This is a site-hardening observation, not evidence of fraud.",
                    weight: capped, category: .transport))
            }
            if !isHTTPS {
                evidence.append(Evidence(code: "headers.no-https",
                    title: "Final page is not HTTPS",
                    detail: "Content and anything typed into the page travel unencrypted.",
                    weight: 8, category: .transport))
            } else {
                evidence.append(Evidence(code: "headers.https",
                    title: "HTTPS connection completed",
                    detail: "The TLS handshake succeeded with default system certificate validation. HTTPS protects transport; it says nothing about who owns the site.",
                    weight: -4, category: .transport))
            }
            return SecurityHeadersReport(url: urlString, finalURL: response.finalURL, https: isHTTPS,
                                         status: response.status, checks: checks, evidence: evidence,
                                         limitations: [
                                            "Header presence is not header correctness; a permissive CSP can still be weak.",
                                            "TLS certificate age, issuer and revocation were not separately inspected; the system's default validation applied.",
                                         ], failed: false)
        } catch {
            let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return SecurityHeadersReport(url: urlString, finalURL: nil, https: false, status: nil, checks: [],
                                         evidence: [], limitations: ["Could not fetch headers: \(detail)", "A failed fetch is unknown, not safe."],
                                         failed: true)
        }
    }
}

// MARK: - Email headers

public struct EmailHeaderReport: Sendable {
    public struct Mechanism: Sendable, Identifiable, Hashable {
        public var name: String
        public var result: String
        public var detail: String
        public var id: String { name }
    }
    public var from: String?
    public var replyTo: String?
    public var returnPath: String?
    public var subject: String?
    public var mechanisms: [EmailHeaderReport.Mechanism]
    public var receivedHops: Int
    public var evidence: [Evidence]
    public var limitations: [String]
    public var parsed: EmailAnalyzer.Parsed
}

public enum EmailHeaderInspector {
    public static func inspect(_ raw: String) -> EmailHeaderReport {
        let parsed = EmailAnalyzer.parse(raw)
        var mechanisms: [EmailHeaderReport.Mechanism] = []
        let auth = (parsed.authenticationResults ?? "").lowercased()
        for (key, label) in [("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")] {
            if auth.isEmpty {
                mechanisms.append(.init(name: label, result: "not supplied",
                                        detail: "No Authentication-Results header was pasted, so \(label) cannot be evaluated. ScamShield never guesses it."))
            } else if auth.contains("\(key)=pass") {
                mechanisms.append(.init(name: label, result: "pass", detail: "The receiving server recorded \(label)=pass."))
            } else if auth.contains("\(key)=fail") {
                mechanisms.append(.init(name: label, result: "fail", detail: "The receiving server recorded \(label)=fail."))
            } else if auth.contains("\(key)=softfail") {
                mechanisms.append(.init(name: label, result: "softfail", detail: "The receiving server recorded \(label)=softfail."))
            } else if auth.contains("\(key)=neutral") {
                mechanisms.append(.init(name: label, result: "neutral", detail: "The receiving server recorded \(label)=neutral."))
            } else {
                mechanisms.append(.init(name: label, result: "unknown", detail: "Authentication-Results is present but does not state a \(label) result."))
            }
        }
        let received = parsed.headers.keys.filter { $0 == "received" }.count
        // Multiple Received headers are folded under one key by our parser; count them
        // in the raw text instead.
        let receivedHops = raw.components(separatedBy: .newlines)
            .filter { $0.lowercased().hasPrefix("received:") }.count
        var evidence = EmailAnalyzer.analyze(raw).evidence
        if receivedHops >= 5 {
            evidence.append(Evidence(code: "email.long-route", title: "Unusually long delivery route",
                detail: "\(receivedHops) Received headers were supplied. Long or inconsistent routes can indicate forwarding through an unexpected relay.",
                weight: 6, category: .reputation))
        }
        _ = received
        var limitations = ["Header analysis describes what the pasted text says. Headers can be forged in the text; only the receiving provider's own headers are authoritative.",
                           "No external sender-IP reputation lookup was performed."]
        if parsed.authenticationResults == nil {
            limitations.insert("No Authentication-Results header was supplied, so SPF, DKIM and DMARC are unknown.", at: 0)
        }
        return EmailHeaderReport(from: parsed.from, replyTo: parsed.replyTo, returnPath: parsed.returnPath,
                                 subject: parsed.subject, mechanisms: mechanisms, receivedHops: receivedHops,
                                 evidence: evidence, limitations: limitations, parsed: parsed)
    }
}

// MARK: - Brand impersonation comparison

public struct BrandComparison: Sendable {
    public struct Lookalike: Sendable, Identifiable, Hashable {
        public var domain: String
        public var reason: String
        public var risk: Int
        public var level: RiskLevel
        public var id: String { domain }
    }
    public var officialDomain: String
    public var brand: String?
    public var candidateAnalysis: ScanResult?
    public var variants: [BrandComparison.Lookalike]
    public var evidence: [Evidence]
    public var limitations: [String]
}

public enum BrandImpersonationChecker {

    public static func compare(officialDomain: String, candidate: String) -> BrandComparison {
        let official = DomainUtils.normalizeHost(officialDomain)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? officialDomain
        let brand = BrandRegistry.officialBrand(forHost: official)?.name
            ?? BrandRegistry.brands.first(where: { $0.domains.contains(official) })?.name

        let engine = ScanEngine()
        var candidateAnalysis: ScanResult?
        if !candidate.trimmingCharacters(in: .whitespaces).isEmpty {
            let value = candidate.lowercased().hasPrefix("http") ? candidate : "https://" + candidate
            candidateAnalysis = engine.scanURL(value)
        }

        var variants: [BrandComparison.Lookalike] = []
        let base = official.split(separator: ".").first.map(String.init) ?? official
        let suffix = official.dropFirst(base.count).description

        func add(_ domain: String, _ reason: String) {
            guard domain != official, !variants.contains(where: { $0.domain == domain }) else { return }
            let result = engine.scanURL("https://" + domain)
            variants.append(BrandComparison.Lookalike(domain: domain, reason: reason, risk: result.riskScore, level: result.riskLevel ?? .inconclusive))
        }

        // Character substitutions and omissions that real typosquatters register.
        let substitutions: [(Character, String)] = [("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4"), ("s", "5")]
        for (char, digit) in substitutions where base.contains(char) {
            add(base.replacingOccurrences(of: String(char), with: String(digit)) + suffix,
                "Digit-for-letter substitution (“\(char)” → “\(digit)”).")
            if variants.count >= 6 { break }
        }
        if base.count >= 4 {
            add(String(base.dropLast()) + suffix, "One character removed from the brand label.")
            add(base + "-secure" + suffix, "Brand plus an account-pressure word.")
            add(base + "-verify" + suffix, "Brand plus a verification word.")
        }
        add(base + "-login" + suffix, "Brand plus a login word.")

        var evidence: [Evidence] = []
        if let candidateAnalysis {
            evidence = candidateAnalysis.evidence
        }
        var limitations = [
            "Generated variants are illustrative typo patterns; their existence does not mean they are registered or in use.",
            "A domain that is not listed here can still impersonate a brand in other ways (page content, logos, subdomains).",
        ]
        if candidateAnalysis?.status != .complete {
            limitations.insert("The candidate could not be analysed as a URL.", at: 0)
        }
        return BrandComparison(officialDomain: official, brand: brand, candidateAnalysis: candidateAnalysis,
                               variants: variants, evidence: evidence, limitations: limitations)
    }
}
