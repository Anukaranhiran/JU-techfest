import Foundation

// MARK: - Scoring

public enum Scoring {

    public struct Outcome: Sendable {
        public var score: Int
        public var level: RiskLevel
        public var confidence: Confidence
    }

    /// Deterministic aggregation: every signal contributes its weight, protective
    /// evidence subtracts, result is clamped to 0...100.
    public static func score(_ evidence: [Evidence]) -> Outcome {
        let raw = evidence.reduce(0) { $0 + $1.weight }
        let score = max(0, min(100, raw))
        let level = RiskLevel.band(forScore: score)
        return Outcome(score: score, level: level, confidence: confidence(for: evidence, score: score))
    }

    static func confidence(for evidence: [Evidence], score: Int) -> Confidence {
        let positives = evidence.filter { $0.weight > 0 }
        let strongest = positives.map(\.weight).max() ?? 0
        let negative = evidence.contains { $0.weight <= -20 }

        if strongest >= 24 || (positives.count >= 3 && score >= 50) { return .high }
        if negative && positives.isEmpty { return .high }
        if positives.isEmpty { return .low }
        if strongest >= 12 { return .medium }
        return .low
    }

    public static func recommendedAction(level: RiskLevel, kind: ScanKind) -> String {
        switch level {
        case .low:
            return "No impersonation or credential-theft signals were found in the URL structure. This is not a guarantee of safety — it means nothing suspicious is visible without visiting the page."
        case .inconclusive:
            return "ScamShield could not verify this destination: the checks that would confirm safety were unavailable, skipped, or the host is temporary. Do not treat this as safe. Open it only if you can verify the sender independently, and never enter credentials."
        case .medium:
            switch kind {
            case .email, .message:
                return "Verify the sender through a channel you already trust before acting. Do not open links from this message until you have confirmed who sent it."
            default:
                return "Open only if you expected this link. If you continue, type nothing and do not sign in until you have confirmed the site independently."
            }
        case .high:
            return "Do not open this link. If you must inspect it, open it in a separate browser profile with no logins and never enter credentials or payment details."
        case .critical:
            return "Do not open this link. Multiple independent signals indicate impersonation or credential theft. Delete the message and report it as phishing."
        }
    }
}

// MARK: - Optional external reputation

public enum ReputationStatus: String, Codable, Sendable {
    case notConfigured
    case clean
    case suspicious
    case malicious
    case unknown
    case error
}

public struct ReputationOutcome: Sendable {
    public var status: ReputationStatus
    public var detail: String
    public var provider: String?

    public init(status: ReputationStatus, detail: String, provider: String? = nil) {
        self.status = status
        self.detail = detail
        self.provider = provider
    }

    public static let notConfigured = ReputationOutcome(
        status: .notConfigured,
        detail: "External reputation lookups are not configured, so only offline structure checks ran."
    )
}

// MARK: - Engine

public struct ScanEngine: Sendable {

    public init() {}

    static let staticLimitations: [String] = [
        "Static analysis only: ScamShield never visits the destination, so page content, forms and redirects after landing are unseen.",
        "Domain age, hosting and certificate history are not available offline.",
        "Heuristics describe what is visible in the URL/text, not proof of intent.",
    ]

    // MARK: URL

    public func scanURL(_ raw: String, source: String? = nil) -> ScanResult {
        let started = Date()
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return failedResult(kind: .url, input: raw, reason: "No URL was supplied.", started: started)
        }

        let parsed: ParsedURL
        do {
            parsed = try ParsedURL.parse(trimmed)
        } catch {
            return failedResult(kind: .url, input: raw, reason: "The text could not be parsed as a URL: \(error.localizedDescription)", started: started)
        }

        var evidence = URLAnalyzer.analyze(parsed)
        var limitations = Self.staticLimitations

        if !parsed.isWebScheme {
            limitations.insert("Non-web schemes are never handed to a browser, so their destination is inherently unverified.", at: 0)
        }
        if DomainUtils.scope(ofHost: parsed.host) == .privateNetwork || DomainUtils.scope(ofHost: parsed.host) == .localhost {
            limitations.insert("This address resolves inside your network. Reputation data about the public internet does not apply to it.", at: 0)
        }
        if URLAnalyzer.shortenerHosts.contains(parsed.registrableDomain) {
            limitations.insert("The link is a shortener: the final destination is chosen server-side when the link is opened.", at: 0)
        }
        let relay = RelayInfrastructure.match(host: parsed.host)
        if let relay, relay.isEndpoint {
            limitations.insert("The host is a \(relay.provider) endpoint, not a permanent domain. Its content can be changed or reused by whoever created it.", at: 0)
        }

        // Nested destination behind a redirect parameter: analyse it once, at reduced
        // weight, so the visible link cannot borrow trust from an outer domain.
        if let nested = Self.nestedDestination(in: parsed), nested.host != parsed.host {
            let nestedEvidence = URLAnalyzer.analyze(nested)
                .filter { $0.weight > 0 }
                .sorted { $0.weight > $1.weight }
                .prefix(2)
            for item in nestedEvidence {
                evidence.append(Evidence(code: "redirect.target." + item.code,
                                         title: "Redirect target: " + item.title,
                                         detail: "Following the redirect parameter leads to \(nested.host). \(item.detail)",
                                         weight: Int(Double(item.weight) * 0.6),
                                         category: item.category))
            }
            limitations.insert("A redirect parameter points to \(nested.host); ScamShield analysed that destination statically but did not follow it.", at: 0)
        }

        let outcome = Scoring.score(evidence)
        let level: RiskLevel
        if !parsed.isWebScheme {
            level = ParsedURL.dangerousSchemes.contains(parsed.scheme) ? .critical : .high
        } else {
            level = outcome.level
        }
        let scoreFloor = level == .critical ? 75 : (level == .high ? 50 : 0)

        var checks: [CheckRecord] = [
            CheckRecord(name: "URL parsing", state: .passed,
                        detail: "Scheme, authority, port, userinfo, path and query parsed as \(parsed.scheme)://\(parsed.host)."),
            CheckRecord(name: "URL structure heuristics", state: .passed,
                        detail: "Typosquatting, homographs, deceptive subdomains, encoding, ports and file names checked."),
            CheckRecord(name: "Relay / dynamic-DNS detection", state: .passed,
                        detail: relay.map { "\($0.provider) \($0.kind.rawValue)\($0.isEndpoint ? " endpoint" : " service")" }
                            ?? "Not a known relay or dynamic-DNS provider."),
            CheckRecord(name: "External reputation", state: .skipped,
                        detail: "No reputation provider is configured. This is not a clean result."),
            CheckRecord(name: "Page content inspection", state: .skipped,
                        detail: "Not part of a structure-only scan; enable a live check to inspect forms and text."),
            CheckRecord(name: "Redirect chain", state: .skipped,
                        detail: "No request was made, so server-side redirects are unknown."),
        ]
        if !parsed.isWebScheme {
            checks.append(CheckRecord(name: "Browser handoff", state: .failed,
                                      detail: "Non-web schemes are never handed to a browser."))
        }

        return ScanResult(
            kind: .url,
            input: String(trimmed.prefix(4000)),
            analyzedURL: parsed.normalized,
            host: parsed.host,
            registrableDomain: parsed.registrableDomain,
            riskScore: max(outcome.score, scoreFloor),
            riskLevel: level,
            status: .complete,
            confidence: outcome.confidence,
            evidence: evidence,
            limitations: Array(limitations.prefix(6)),
            recommendedAction: Scoring.recommendedAction(level: level, kind: .url),
            skippedChecks: ["External reputation (not configured)", "Domain registration age", "Redirect chain after opening"],
            checks: checks,
            evidenceSources: ["Local heuristics"],
            createdAt: started,
            durationMs: Date().timeIntervalSince(started) * 1000
        )
    }

    // MARK: Message / pasted text

    public func scanMessage(_ text: String) -> ScanResult {
        let started = Date()
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 3 else {
            return failedResult(kind: .message, input: text, reason: "Paste at least a few words to analyse.", started: started)
        }

        let textResult = TextAnalyzer.analyze(trimmed)
        var evidence = textResult.evidence
        var limitations = [
            "Only the text you pasted was analysed; attachments and images were not opened.",
            "ScamShield does not know who sent the message or whether the sender is genuine.",
        ]

        // Scan every embedded link and fold the worst one in.
        var worstURL: ScanResult?
        for link in textResult.links.prefix(5) {
            let result = scanURL(link)
            if let level = result.riskLevel, level >= (worstURL?.riskLevel ?? .low) {
                worstURL = result
            }
        }
        if let worstURL, let level = worstURL.riskLevel {
            evidence.append(contentsOf: worstURL.topEvidence.prefix(4).map { item in
                Evidence(code: "link." + item.code, title: "Link: " + item.title,
                         detail: item.detail, weight: item.weight, category: item.category)
            })
            if level >= .medium {
                limitations.insert("One of the embedded links is the main risk here — see the link evidence.", at: 0)
            }
        }

        let outcome = Scoring.score(evidence)
        var level = outcome.level
        if let worstLevel = worstURL?.riskLevel, worstLevel > level { level = worstLevel }

        return ScanResult(
            kind: .message,
            input: String(trimmed.prefix(4000)),
            analyzedURL: worstURL?.analyzedURL,
            host: worstURL?.host,
            registrableDomain: worstURL?.registrableDomain,
            riskScore: max(outcome.score, worstURL?.riskScore ?? 0),
            riskLevel: level,
            status: .complete,
            confidence: worstURL.map { $0.confidence.rank >= outcome.confidence.rank ? $0.confidence : outcome.confidence } ?? outcome.confidence,
            evidence: evidence,
            limitations: limitations,
            recommendedAction: Scoring.recommendedAction(level: level, kind: .message),
            skippedChecks: textResult.links.isEmpty ? ["No links present in the text"] : ["Sender reputation", "Attachment inspection"],
            createdAt: started,
            durationMs: Date().timeIntervalSince(started) * 1000
        )
    }

    // MARK: Email

    public func scanEmail(_ raw: String) -> ScanResult {
        let started = Date()
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 5 else {
            return failedResult(kind: .email, input: raw, reason: "Paste the email (headers and body) to analyse it.", started: started)
        }

        let analysis = EmailAnalyzer.analyze(trimmed)
        var evidence = analysis.evidence
        var limitations = analysis.limitations

        let bodyLinks = LinkExtractor.links(in: analysis.parsed.body)
        var worstURL: ScanResult?
        for link in bodyLinks.prefix(6) {
            let result = scanURL(link)
            if let level = result.riskLevel, level >= (worstURL?.riskLevel ?? .low) { worstURL = result }
        }
        if let worstURL, let level = worstURL.riskLevel {
            evidence.append(contentsOf: worstURL.topEvidence.prefix(3).map {
                Evidence(code: "email.link." + $0.code, title: "Body link: " + $0.title, detail: $0.detail, weight: $0.weight, category: $0.category)
            })
            limitations.insert("Links in the body were analysed structurally only; none were opened.", at: 0)
            _ = level
        }

        let outcome = Scoring.score(evidence)
        var level = outcome.level
        if let worstLevel = worstURL?.riskLevel, worstLevel > level { level = worstLevel }
        if analysis.parsed.authenticationResults == nil && level < .medium && analysis.evidence.contains(where: { $0.code == "email.display-name-spoof" }) {
            level = .medium
        }

        return ScanResult(
            kind: .email,
            input: String(trimmed.prefix(4000)),
            analyzedURL: worstURL?.analyzedURL,
            host: worstURL?.host,
            registrableDomain: worstURL?.registrableDomain,
            riskScore: max(outcome.score, worstURL?.riskScore ?? 0),
            riskLevel: level,
            status: .complete,
            confidence: outcome.confidence,
            evidence: evidence,
            limitations: limitations,
            recommendedAction: Scoring.recommendedAction(level: level, kind: .email),
            skippedChecks: analysis.parsed.authenticationResults == nil
                ? ["SPF/DKIM/DMARC (no Authentication-Results header)", "Sender IP reputation"]
                : ["Sender IP reputation"],
            createdAt: started,
            durationMs: Date().timeIntervalSince(started) * 1000
        )
    }

    /// First absolute URL found in a redirect-style query parameter, if any.
    static func nestedDestination(in url: ParsedURL) -> ParsedURL? {
        for (name, value) in URLAnalyzer.queryPairs(url.query) {
            let looksLikeLink = value.lowercased().hasPrefix("http://") || value.lowercased().hasPrefix("https://")
            guard looksLikeLink || URLAnalyzer.redirectParams.contains(name.lowercased()) else { continue }
            if let parsed = try? ParsedURL.parse(value), parsed.host != url.host { return parsed }
        }
        return nil
    }

    // MARK: Failure paths

    func failedResult(kind: ScanKind, input: String, reason: String, started: Date) -> ScanResult {
        ScanResult(
            kind: kind,
            input: String(input.prefix(4000)),
            riskScore: 0,
            riskLevel: nil,
            status: .failed,
            confidence: .low,
            evidence: [],
            limitations: [reason, "Because the scan did not complete, this input is UNVERIFIED — it must not be treated as safe."],
            recommendedAction: "ScamShield could not analyse this input. Do not open it unless you can verify the source yourself.",
            skippedChecks: ["All deterministic checks"],
            createdAt: started,
            durationMs: Date().timeIntervalSince(started) * 1000
        )
    }

    // MARK: Reputation merge

    /// Folds an optional external reputation result into a completed scan.
    /// Failure or absence never upgrades a verdict to safe: it only adds a limitation.
    public func applyingReputation(_ result: ScanResult, outcome: ReputationOutcome) -> ScanResult {
        var updated = result
        switch outcome.status {
        case .malicious:
            updated.evidence.append(Evidence(code: "reputation.malicious",
                title: "Flagged by external reputation",
                detail: outcome.detail, weight: 80, category: .reputation))
            updated.limitations.insert("External reputation matched this URL. The match is reported verbatim and not interpreted locally.", at: 0)
        case .suspicious:
            updated.evidence.append(Evidence(code: "reputation.suspicious",
                title: "Flagged as suspicious by external reputation",
                detail: outcome.detail, weight: 45, category: .reputation))
            updated.limitations.insert("A reputation provider marked this URL suspicious. Provider judgement is reported verbatim.", at: 0)
        case .clean:
            // No listing is not protective evidence against an observed phishing page.
            // Keep one attributed observation, with no risk discount.
            if !updated.evidence.contains(where: { $0.code == "reputation.clean" }) {
                updated.evidence.append(Evidence(code: "reputation.clean",
                    title: "No external reputation match",
                    detail: outcome.detail, weight: 0, category: .reputation))
            }
        case .unknown:
            updated.limitations.insert("External reputation returned no information (status: unknown). That is not a clearance.", at: 0)
        case .error:
            updated.limitations.insert("External reputation lookup failed: \(outcome.detail). The offline verdict below is unaffected.", at: 0)
            updated.skippedChecks.append("External reputation (failed, not a clearance)")
        case .notConfigured:
            updated.skippedChecks.append("External reputation (not configured)")
        }
        if let provider = outcome.provider, outcome.status != .notConfigured {
            var sources = updated.evidenceSources ?? []
            if !sources.contains(provider) { sources.append(provider) }
            updated.evidenceSources = sources
        }
        updated.checks = (updated.checks ?? []).map { check in
            guard check.name == "External reputation" else { return check }
            var updatedCheck = check
            switch outcome.status {
            case .clean, .malicious, .suspicious, .unknown:
                updatedCheck.state = .passed
                updatedCheck.detail = "\(outcome.provider ?? "Provider"): \(outcome.status.rawValue) — \(outcome.detail)"
            case .error:
                updatedCheck.state = .failed
                updatedCheck.detail = "\(outcome.provider ?? "Provider") failed: \(outcome.detail)"
            case .notConfigured:
                updatedCheck.state = .skipped
                updatedCheck.detail = outcome.detail
            }
            return updatedCheck
        }

        let outcomeScore = Scoring.score(updated.evidence)
        var level = max(outcomeScore.level, result.riskLevel ?? .low)
        // A relay/dynamic host never falls back to "low" merely because a provider
        // has no listing for it.
        if level == .low, updated.evidence.contains(where: { $0.code == "host.ephemeral-tunnel" || $0.code == "host.dynamic-dns" }) {
            level = .inconclusive
        }
        updated.riskScore = max(result.riskScore, outcomeScore.score)
        updated.riskLevel = level
        updated.confidence = outcomeScore.confidence
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: updated.kind)
        return updated
    }
}

public extension Confidence {
    var rank: Int {
        switch self {
        case .low: return 0
        case .medium: return 1
        case .high: return 2
        }
    }
}

// MARK: - Live text/email/QR pipelines
//
// The structural analysers above stay deterministic and offline. These wrappers run
// the *same* live URL pipeline used by the Link Scanner and browser extension for
// every embedded link, then merge the result without erasing message-level evidence.

public extension ScanEngine {

    func liveScanMessage(_ text: String, config: ReputationProviderConfig,
                         ai: AIProviderConfig? = nil) async -> ScanResult {
        let base = scanMessage(text)
        guard base.status == .complete else { return base }
        let links = Array(LinkExtractor.links(in: text).prefix(5))
        guard !links.isEmpty else { return base }

        var worst: ScanResult?
        for link in links {
            let scanned = await liveScan(link, config: config, ai: nil)
            if let level = scanned.riskLevel, level >= (worst?.riskLevel ?? .low) {
                worst = scanned
            }
        }
        guard let worst else { return base }
        return mergeLiveLink(into: base, link: worst, kind: .message,
                             prefix: "link.", label: "Link")
    }

    func liveScanEmail(_ raw: String, config: ReputationProviderConfig,
                       ai: AIProviderConfig? = nil) async -> ScanResult {
        let base = scanEmail(raw)
        guard base.status == .complete else { return base }
        let parsed = EmailAnalyzer.analyze(raw).parsed
        let links = Array(LinkExtractor.links(in: parsed.body).prefix(6))
        guard !links.isEmpty else { return base }

        var worst: ScanResult?
        for link in links {
            let scanned = await liveScan(link, config: config, ai: nil)
            if let level = scanned.riskLevel, level >= (worst?.riskLevel ?? .low) {
                worst = scanned
            }
        }
        guard let worst else { return base }
        return mergeLiveLink(into: base, link: worst, kind: .email,
                             prefix: "email.link.", label: "Body link")
    }

    func liveScanQRImage(_ data: Data, config: ReputationProviderConfig,
                         ai: AIProviderConfig? = nil) async -> ScanResult {
        let started = Date()
        let decoded = MediaAnalyzer.decodeBarcodes(from: data)
        if let error = decoded.error {
            return failedResult(kind: .qr, input: "<image \(data.count) bytes>", reason: error, started: started)
        }
        guard let payload = decoded.payloads.first else {
            return failedResult(kind: .qr, input: "<image \(data.count) bytes>",
                                reason: "No QR or barcode was found in this image. Nothing was verified.",
                                started: started)
        }
        let looksLikeURL = payload.lowercased().hasPrefix("http://") || payload.lowercased().hasPrefix("https://")
        var base = looksLikeURL
            ? await liveScan(payload, config: config, ai: ai)
            : await liveScanMessage(payload, config: config, ai: ai)
        base.kind = .qr
        base.input = "QR payload: \(payload.prefix(500))"
        base.limitations.insert("Decoded \(decoded.symbologies.first ?? "barcode") payload: “\(payload.prefix(160))”.", at: 0)
        base.limitations.insert("A QR code can hide its destination; the printed image proves nothing about who made it.", at: 1)
        if !looksLikeURL {
            base.limitations.insert("The QR payload is not a web link, so it was analysed as message text.", at: 0)
        }
        base.skippedChecks.append("Visual/physical tampering checks on the code image")
        base.durationMs = Date().timeIntervalSince(started) * 1000
        return base
    }

    func liveScanScreenshot(_ data: Data, config: ReputationProviderConfig,
                            ai: AIProviderConfig? = nil) async -> ScanResult {
        let started = Date()
        let ocr = MediaAnalyzer.recognizeText(from: data)
        if let error = ocr.error {
            return failedResult(kind: .screenshot, input: "<image \(data.count) bytes>", reason: error, started: started)
        }
        let text = ocr.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count >= 3 else {
            return failedResult(kind: .screenshot, input: "<image \(data.count) bytes>",
                                reason: "OCR found no readable text in the screenshot. Nothing was verified.",
                                started: started)
        }
        var base = await liveScanMessage(text, config: config, ai: ai)
        base.kind = .screenshot
        base.input = "Screenshot OCR (\(text.count) chars): \(text.prefix(400))"
        base.limitations.insert("Text recognised locally with average OCR confidence \(String(format: "%.0f%%", ocr.confidence * 100)).", at: 0)
        base.limitations.append(contentsOf: MediaAnalyzer.ocrLimitations.prefix(2))
        base.skippedChecks.append("Logo/pixel forensics")
        if ocr.confidence < 0.4 {
            base.limitations.insert("OCR confidence is low, so the extracted text may be incomplete — treat the verdict as a partial check.", at: 0)
            base.confidence = .low
        }
        base.durationMs = Date().timeIntervalSince(started) * 1000
        return base
    }

    /// Keeps text/message evidence and adds the URL-level verdict, without double
    /// counting the same evidence already folded by the structural scan.
    func mergeLiveLink(into base: ScanResult, link: ScanResult, kind: ScanKind,
                               prefix: String, label: String) -> ScanResult {
        var updated = base
        updated.analyzedURL = link.analyzedURL ?? base.analyzedURL
        updated.host = link.host ?? base.host
        updated.registrableDomain = link.registrableDomain ?? base.registrableDomain

        for item in link.topEvidence.prefix(4) {
            let code = prefix + item.code
            if !updated.evidence.contains(where: { $0.code == code }) {
                updated.evidence.append(Evidence(code: code,
                    title: "\(label): " + item.title, detail: item.detail,
                    weight: item.weight, category: item.category))
            }
        }
        for item in link.evidence where item.category == .reputation && item.weight > 0 {
            if !updated.evidence.contains(where: { $0.code == prefix + item.code }) {
                updated.evidence.append(Evidence(code: prefix + item.code,
                    title: "\(label): " + item.title, detail: item.detail,
                    weight: item.weight, category: .reputation))
            }
        }

        var checks = updated.checks ?? []
        for check in link.checks ?? [] {
            let name = "\(label) · \(check.name)"
            if !checks.contains(where: { $0.name == name && $0.detail == check.detail }) {
                checks.append(CheckRecord(name: name, state: check.state, detail: check.detail))
            }
        }
        updated.checks = checks

        var sources = updated.evidenceSources ?? []
        for source in link.evidenceSources ?? [] where !sources.contains(source) {
            sources.append(source)
        }
        updated.evidenceSources = sources

        updated.limitations.append("The embedded \(label.lowercased()) was checked with the full live URL pipeline\(link.riskLevel.map { " (\($0.title))" } ?? "").")
        updated.limitations.removeAll { $0.contains("analysed structurally only") }
        for limitation in link.limitations where !updated.limitations.contains(limitation) {
            updated.limitations.append(limitation)
        }

        let outcome = Scoring.score(updated.evidence)
        var level = max(outcome.level, base.riskLevel ?? .low, link.riskLevel ?? .low)
        if link.status != .complete, level < .inconclusive { level = .inconclusive }
        updated.riskLevel = level
        updated.riskScore = max(base.riskScore, link.riskScore, outcome.score,
                                level == .critical ? 75 : (level == .high ? 50 : 0))
        updated.confidence = max(base.confidence, link.confidence)
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: kind)
        updated.durationMs = max(updated.durationMs, Date().timeIntervalSince(updated.createdAt) * 1000)
        return updated
    }
}
