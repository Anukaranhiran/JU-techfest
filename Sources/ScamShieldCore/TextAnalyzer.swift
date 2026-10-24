import Foundation

// MARK: - Link extraction

public enum LinkExtractor {
    public static func links(in text: String) -> [String] {
        var found: [String] = []
        // NSDataDetector is good at real sentences; regex catches the rest (hxxp, defanged links).
        if let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) {
            detector.enumerateMatches(in: text, options: [], range: NSRange(location: 0, length: text.utf16.count)) { match, _, _ in
                if let url = match?.url?.absoluteString, !found.contains(url) { found.append(url) }
            }
        }
        let pattern = #"(?i)\b(hxxps?|https?):\/\/[^\s<>"'\)\]]+"#
        if let regex = try? NSRegularExpression(pattern: pattern) {
            let ns = text as NSString
            regex.enumerateMatches(in: text, options: [], range: NSRange(location: 0, length: ns.length)) { match, _, _ in
                guard let range = match?.range else { return }
                var raw = ns.substring(with: range)
                raw = raw.replacingOccurrences(of: "hxxp", with: "http", options: .caseInsensitive)
                raw = raw.replacingOccurrences(of: "hxxps", with: "https", options: .caseInsensitive)
                raw = raw.trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?"))
                if !found.contains(raw) { found.append(raw) }
            }
        }
        return found
    }

    /// Defanged indicators such as `evil[.]example[.]com`.
    public static func refanged(_ text: String) -> String {
        text.replacingOccurrences(of: "[.]", with: ".")
            .replacingOccurrences(of: "(.)", with: ".")
            .replacingOccurrences(of: "[:]", with: ":")
            .replacingOccurrences(of: "hxxp", with: "http", options: .caseInsensitive)
    }
}

// MARK: - Social-engineering language

public enum TextAnalyzer {

    struct Rule {
        let code: String
        let title: String
        let patterns: [String]
        let weight: Int
        let detail: String
        let category: Evidence.Category
    }

    static let rules: [Rule] = [
        Rule(code: "text.urgency", title: "Manufactured urgency",
             patterns: ["urgent", "immediately", "within 24 hours", "within 24hrs", "within 48 hours", "last warning",
                        "final notice", "act now", "expires today", "expires in", "before it's too late", "asap",
                        "right away", "time is running out", "hours left", "deadline"],
             weight: 10, detail: "Time pressure is used to stop you checking.", category: .content),
        Rule(code: "text.threat", title: "Threat of loss or suspension",
             patterns: ["account will be suspended", "account suspended", "will be locked", "permanently closed",
                        "legal action", "law enforcement", "arrest", "fine", "penalty", "deactivated", "terminated",
                        "your account has been", "unusual activity", "unauthorized access", "security alert"],
             weight: 12, detail: "Threats of closure or legal action push victims to act without verifying.", category: .content),
        Rule(code: "text.payment", title: "Payment or money transfer request",
             patterns: ["gift card", "itunes card", "google play card", "steam card", "wire transfer", "bank transfer",
                        "western union", "moneygram", "zelle", "venmo", "cash app", "bitcoin", "btc", "usdt",
                        "crypto wallet", "ethereum", "send funds", "processing fee", "release fee", "customs fee",
                        "gift cards", "payment required", "pay the fee"],
             weight: 16, detail: "Irreversible payment rails are the preferred settlement method for scams.", category: .content),
        Rule(code: "text.otp", title: "Requests a one-time code or password",
             patterns: ["one-time code", "one time password", "otp", "verification code", "2fa code", "authenticator code",
                        "send me the code", "share the code", "read me the code", "six digit", "6-digit", "your password",
                        "confirm your password", "enter your pin", "your pin"],
             weight: 20, detail: "No legitimate support agent ever needs your one-time code or password.", category: .content),
        Rule(code: "text.remote-tools", title: "Remote-access software requested",
             patterns: ["anydesk", "teamviewer", "remote desktop", "screen sharing", "install this app", "download this tool",
                        "allow remote access", "supremo", "rustdesk", "logmein", "quick assist"],
             weight: 20, detail: "Remote-access tools give an attacker direct control of your Mac.", category: .content),
        Rule(code: "text.credentials", title: "Credential or identity harvesting",
             patterns: ["confirm your identity", "verify your account", "update your payment", "re-enter your card",
                        "social security", "ssn", "national insurance", "date of birth", "mother's maiden name",
                        "billing information", "card number", "cvv", "expiry date", "bank details", "seed phrase",
                        "recovery phrase", "private key", "wallet phrase"],
             weight: 18, detail: "Requests for secrets, card data or identity details over chat/mail are a phishing hallmark.", category: .content),
        Rule(code: "text.secrecy", title: "Asks you to keep it secret",
             patterns: ["don't tell", "do not tell", "keep this confidential", "between us", "don't mention",
                        "no one else", "keep it quiet"],
             weight: 14, detail: "Isolation from people who could sanity-check the request is a manipulation tactic.", category: .content),
        Rule(code: "text.impersonation", title: "Claims to be an authority",
             patterns: ["this is apple support", "microsoft support", "amazon security", "paypal security team",
                        "your bank", "the police", "government agency", "internal revenue", "hmrc", "irs",
                        "fraud department", "security team", "we detected", "our system shows", "customer support team"],
             weight: 9, detail: "Claims of authority are trivial to type and prove nothing.", category: .content),
        Rule(code: "text.reward", title: "Unexpected reward or refund",
             patterns: ["you've won", "you have won", "congratulations", "claim your prize", "free gift",
                        "refund is ready", "tax refund", "unclaimed", "lottery", "giveaway", "selected winner",
                        "airdrop", "bonus", "voucher"],
             weight: 12, detail: "Unsolicited winnings and refunds are bait for credential or payment capture.", category: .content),
        Rule(code: "text.delivery", title: "Fake delivery/customs story",
             patterns: ["parcel is waiting", "delivery failed", "redelivery fee", "customs clearance", "shipping fee",
                        "your package", "courier could not", "reschedule delivery", "tracking number"],
             weight: 10, detail: "Delivery-fee lures are among the most common SMS/email scams.", category: .content),
        Rule(code: "text.investment", title: "Investment or crypto pitch",
             patterns: ["guaranteed returns", "risk-free", "double your", "investment opportunity", "trading bot",
                        "pump", "presale", "early access token", "wallet validation", "sync your wallet"],
             weight: 12, detail: "Guaranteed-return offers and wallet “validation” requests are classic fraud.", category: .content),
        Rule(code: "text.offplatform", title: "Moves the conversation off-platform",
             patterns: ["message me on whatsapp", "text me at", "contact me on telegram", "add me on telegram",
                        "email me at", "call this number", "dm me"],
             weight: 7, detail: "Moving to a channel you cannot verify removes platform protections.", category: .content),
    ]

    public struct Result: Sendable {
        public var evidence: [Evidence]
        public var links: [String]
        public var matchedRules: [String]
    }

    public static func analyze(_ text: String) -> Result {
        let lower = text.lowercased()
        var evidence: [Evidence] = []
        var matched: [String] = []

        for rule in rules {
            let hits = rule.patterns.filter { lower.contains($0) }
            guard !hits.isEmpty else { continue }
            matched.append(rule.code)
            evidence.append(Evidence(
                code: rule.code,
                title: rule.title,
                detail: "\(rule.detail) Matched: “\(hits.prefix(3).joined(separator: "”, “"))”.",
                weight: rule.weight,
                category: rule.category
            ))
        }

        let links = LinkExtractor.links(in: text) + LinkExtractor.links(in: LinkExtractor.refanged(text))

        // Combination effects: a link plus pressure is much stronger than either alone.
        if !links.isEmpty {
            if matched.contains("text.otp") && (matched.contains("text.urgency") || matched.contains("text.threat")) {
                evidence.append(Evidence(code: "text.combo-otp-link",
                    title: "Code request + pressure + link",
                    detail: "The message pairs a one-time-code request with urgency or a threat and includes a link. That combination is the standard account-takeover script.",
                    weight: 22, category: .content))
            }
            if matched.contains("text.payment") && matched.contains("text.impersonation") {
                evidence.append(Evidence(code: "text.combo-payment-authority",
                    title: "Payment demand from a claimed authority",
                    detail: "An unverified sender claims authority while demanding an irreversible payment.",
                    weight: 14, category: .content))
            }
        }

        if !links.isEmpty && matched.isEmpty && evidence.isEmpty {
            evidence.append(Evidence(code: "text.no-pressure-language",
                title: "No social-engineering language detected",
                detail: "The text did not match known pressure, payment, code-request or remote-access scripts. This does not vouch for any link inside it.",
                weight: -3, category: .content))
        }

        return Result(evidence: evidence, links: Array(Set(links)), matchedRules: matched)
    }
}

// MARK: - Email header analysis

public enum EmailAnalyzer {

    public struct Parsed: Sendable {
        public var from: String?
        public var replyTo: String?
        public var returnPath: String?
        public var subject: String?
        public var authenticationResults: String?
        public var receivedSPF: String?
        public var body: String
        public var headers: [String: String]
    }

    public static func parse(_ raw: String) -> Parsed {
        var headers: [String: String] = [:]
        var bodyLines: [String] = []
        var inBody = false
        var lastKey: String?

        for line in raw.components(separatedBy: .newlines) {
            if !inBody {
                if line.trimmingCharacters(in: .whitespaces).isEmpty {
                    inBody = true
                    lastKey = nil
                    continue
                }
                if line.hasPrefix(" ") || line.hasPrefix("\t"), let key = lastKey {
                    headers[key, default: ""] += " " + line.trimmingCharacters(in: .whitespaces)
                    continue
                }
                if let colon = line.firstIndex(of: ":") {
                    let key = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
                    let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                    headers[key] = value
                    lastKey = key
                    continue
                }
            }
            bodyLines.append(line)
        }

        return Parsed(
            from: headers["from"],
            replyTo: headers["reply-to"],
            returnPath: headers["return-path"],
            subject: headers["subject"],
            authenticationResults: headers["authentication-results"],
            receivedSPF: headers["received-spf"],
            body: bodyLines.joined(separator: "\n"),
            headers: headers
        )
    }

    /// Extracts the address part of `Name <user@host>`.
    static func address(in value: String?) -> String? {
        guard let value else { return nil }
        if let start = value.lastIndex(of: "<"), let end = value.lastIndex(of: ">"), start < end {
            return String(value[value.index(after: start)..<end]).trimmingCharacters(in: .whitespaces)
        }
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed.contains("@") ? trimmed : nil
    }

    static func displayName(in value: String?) -> String? {
        guard let value, let start = value.lastIndex(of: "<") else { return nil }
        var name = String(value[value.startIndex..<start]).trimmingCharacters(in: .whitespaces)
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        return name.isEmpty ? nil : name
    }

    static func domain(of address: String?) -> String? {
        guard let address, let at = address.lastIndex(of: "@") else { return nil }
        let host = String(address[address.index(after: at)...])
        return DomainUtils.registrableDomain(host)
    }

    public static func analyze(_ raw: String) -> (evidence: [Evidence], limitations: [String], parsed: Parsed) {
        let parsed = parse(raw)
        var evidence: [Evidence] = []
        var limitations: [String] = []

        let fromAddress = address(in: parsed.from)
        let fromDomain = domain(of: fromAddress)
        let replyDomain = domain(of: address(in: parsed.replyTo))
        let returnDomain = domain(of: parsed.returnPath)

        if parsed.from == nil {
            limitations.append("No From header found. Paste the full raw message (including headers) for sender checks.")
        }

        if let fromDomain, let replyDomain, fromDomain != replyDomain {
            evidence.append(Evidence(code: "email.reply-to-mismatch",
                title: "Reply-To points to a different domain",
                detail: "From is @\(fromDomain) but Reply-To is @\(replyDomain). Replies would go somewhere else than the apparent sender.",
                weight: 20, category: .domain))
        }
        if let fromDomain, let returnDomain, fromDomain != returnDomain, returnDomain != "bounce." + fromDomain {
            evidence.append(Evidence(code: "email.return-path-mismatch",
                title: "Return-Path differs from From",
                detail: "The envelope sender (@\(returnDomain)) does not match the displayed sender (@\(fromDomain)), which is common in spoofing.",
                weight: 12, category: .domain))
        }

        // Display-name spoofing: "Apple Support <random@gmail.com>"
        if let display = displayName(in: parsed.from) {
            let displayLower = display.lowercased()
            if let brand = BrandRegistry.brands.first(where: { b in b.tokens.contains { displayLower.contains($0) } }) {
                if let fromDomain, !BrandRegistry.isOfficial(host: fromDomain, for: brand) {
                    evidence.append(Evidence(code: "email.display-name-spoof",
                        title: "Display name claims \(brand.name)",
                        detail: "The name says “\(display)” but the actual sending domain is @\(fromDomain), not \(brand.domains[0]).",
                        weight: 26, category: .brand))
                }
            }
            if display.contains("@"), let displayDomain = display.split(separator: "@").last.map(String.init) {
                let d = DomainUtils.registrableDomain(displayDomain.lowercased())
                if let fromDomain, d != fromDomain {
                    evidence.append(Evidence(code: "email.address-in-display-name",
                        title: "An email address inside the display name",
                        detail: "The display name shows @\(d) while the message really comes from @\(fromDomain).",
                        weight: 18, category: .brand))
                }
            }
        }

        // Authentication results, when the pasted headers include them.
        if let auth = parsed.authenticationResults?.lowercased() {
            for (mechanism, label) in [("spf=fail", "SPF"), ("dkim=fail", "DKIM"), ("dmarc=fail", "DMARC")] {
                if auth.contains(mechanism) {
                    evidence.append(Evidence(code: "email.auth-\(label.lowercased())",
                        title: "\(label) authentication failed",
                        detail: "The receiving server recorded \(label) failure for this message — the sending domain was not authorised.",
                        weight: 28, category: .reputation))
                }
            }
            if auth.contains("spf=pass") && auth.contains("dkim=pass") && auth.contains("dmarc=pass") {
                evidence.append(Evidence(code: "email.auth-pass",
                    title: "SPF, DKIM and DMARC passed",
                    detail: "The receiving server authenticated the sending domain. This proves the domain sent it, not that the content is trustworthy.",
                    weight: -12, category: .reputation))
            }
        } else {
            limitations.append("No Authentication-Results header in the pasted text, so SPF/DKIM/DMARC could not be checked. ScamShield never guesses these.")
        }

        if let fromDomain, let fromAddress,
           ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "aol.com", "proton.me", "gmx.com"].contains(fromDomain),
           let display = displayName(in: parsed.from)?.lowercased(),
           BrandRegistry.brands.contains(where: { $0.tokens.contains { display.contains($0) } }) {
            evidence.append(Evidence(code: "email.freemail-brand",
                title: "Brand name from a free mailbox",
                detail: "A company does not send account-security mail from \(fromAddress).",
                weight: 22, category: .brand))
        }

        let textResult = TextAnalyzer.analyze(parsed.body.isEmpty ? raw : parsed.body)
        evidence.append(contentsOf: textResult.evidence)

        for link in textResult.links.prefix(4) {
            if let parsedURL = try? ParsedURL.parse(link),
               let official = BrandRegistry.officialBrand(forHost: parsedURL.host) {
                evidence.append(Evidence(code: "email.link-official",
                    title: "Body links to an official \(official.name) domain",
                    detail: "One body link resolves to \(parsedURL.registrableDomain).",
                    weight: -4, category: .domain))
                break
            }
        }

        if parsed.subject?.isEmpty ?? true {
            limitations.append("No Subject header was found.")
        }

        return (evidence, limitations, parsed)
    }
}
