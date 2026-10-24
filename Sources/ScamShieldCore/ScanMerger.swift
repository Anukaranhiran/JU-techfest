import Foundation

// MARK: - Merging independent checks into one evidence-based verdict
//
// Every optional check contributes evidence through the same Scoring function. Checks
// that failed cannot lower the score; they add a limitation and a failed CheckRecord.
// This prevents an unavailable provider from quietly turning into "safe".

public extension ScanEngine {

    func applyingPageInspection(_ result: ScanResult, inspection: PageInspection) -> ScanResult {
        var updated = result
        updated.evidence.append(contentsOf: inspection.evidence)
        updated.checks = (updated.checks ?? []) + inspection.checks
        var sources = updated.evidenceSources ?? []
        if !sources.contains("Page inspection") { sources.append("Page inspection") }
        updated.evidenceSources = sources

        // The base scan is structure-only. Once the page has actually been fetched,
        // that limitation is no longer true and must not be shown alongside a real
        // page inspection.
        updated.limitations.removeAll { $0.hasPrefix("Static analysis only:") }
        if !inspection.contentAvailable {
            updated.limitations.insert("Only URL heuristics could be assessed; the requested page content was not available for inspection.", at: 0)
        }
        for limitation in inspection.limitations where !updated.limitations.contains(limitation) {
            updated.limitations.append(limitation)
        }
        updated.checks = (updated.checks ?? []).map { check in
            guard check.name == "Page content inspection" else { return check }
            var updatedCheck = check
            if let status = inspection.httpStatus {
                updatedCheck.state = inspection.contentAvailable && !inspection.truncated ? .passed : .failed
                updatedCheck.detail = inspection.contentAvailable
                    ? "HTTP \(status); \(inspection.truncated ? "partial HTML only; later content is unknown" : "static HTML forms and text inspected")."
                    : "HTTP \(status); the requested page was unavailable, empty or unsupported. Content was not verified."
            } else {
                updatedCheck.state = .failed
                updatedCheck.detail = "The page could not be fetched. Content was not inspected, which is not a clearance."
            }
            return updatedCheck
        }
        if inspection.httpStatus == nil {
            updated.limitations.insert("The page itself could not be fetched, so content-based clearance did not happen. Unreachable is not safe.", at: 0)
        }
        if let finalURL = inspection.finalURL,
           let initial = updated.analyzedURL,
           (try? ParsedURL.parse(finalURL))?.host != (try? ParsedURL.parse(initial))?.host {
            updated.limitations.insert("The page was served from \(finalURL), a different host than the submitted link.", at: 0)
        }

        // Fold evidence from destinations that were actually fetched. This is what
        // distinguishes a landing page that merely links to Instagram from one whose
        // Visit button opens a fake login. Destination evidence is attributed to the
        // URL that supplied it and is not presented as if it came from the landing page.
        for destination in inspection.destinationInspections {
            let target = destination.finalURL ?? destination.requestedURL
            if destination.contentAvailable {
                let top = destination.evidence.filter { $0.weight > 0 }
                    .sorted { $0.weight > $1.weight }
                    .prefix(4)
                for item in top {
                    let code = "landing." + item.code
                    if !updated.evidence.contains(where: { $0.code == code && $0.detail == item.detail }) {
                        updated.evidence.append(Evidence(
                            code: code,
                            title: "Destination \(URL(string: target)?.host ?? target): \(item.title)",
                            detail: item.detail,
                            weight: max(1, Int(Double(item.weight) * 0.85)),
                            category: item.category))
                    }
                }
            } else {
                updated.limitations.append("A discovered destination could not be inspected: \(target). It is unverified, not safe.")
            }
            updated.checks = (updated.checks ?? []) + [
                CheckRecord(name: "Destination · \(URL(string: target)?.host ?? target)",
                            state: destination.contentAvailable ? .passed : .unavailable,
                            detail: destination.httpStatus.map { status in
                                "HTTP \(status); \(destination.bodyBytes) bytes; password form: \(destination.hasPasswordForm); brand impersonation: \(destination.hasBrandImpersonation)."
                            } ?? "The destination could not be fetched, so its content was not verified.")
            ]
        }
        if !inspection.destinations.filter(\.isExternal).isEmpty {
            let fetchedHosts = Set(inspection.destinationInspections.compactMap { $0.finalURL.flatMap { URL(string: $0)?.host } })
            let discoveredHosts = inspection.destinations.filter(\.isExternal).compactMap(\.host)
            let uninspected = discoveredHosts.filter { !fetchedHosts.contains($0) }
            if !uninspected.isEmpty {
                updated.limitations.append("The page links to \(uninspected.count) external host(s) that were not fetched: \(uninspected.prefix(4).joined(separator: ", ")).")
            }
        }

        let outcome = Scoring.score(updated.evidence)
        var level = outcome.level
        // A page that never loaded, or returned an error, did not provide content we
        // can judge. Infrastructure-only evidence must not be presented as a
        // content verdict: the result is INCONCLUSIVE unless independent URL evidence
        // is already strong (high/critical).
        let pageUnavailable = !inspection.contentAvailable || inspection.truncated
        if pageUnavailable, level < .high {
            level = .inconclusive
        }
        // A live page with a credential form posting off-domain is strong enough to warn.
        if inspection.hasCredentialExternalForm, level < .high { level = .high }

        // Page-level phishing pattern: collected credentials plus at least one
        // independent impersonation/pressure signal. Any one of these alone can be
        // innocent; together they describe a fake login.
        let pageCodes = Set(inspection.evidence.map(\.code))
        let credentialCollection = inspection.hasPasswordForm || inspection.hasPaymentForm
        let impersonationOrPressure = pageCodes.contains("page.brand-impersonation")
            || pageCodes.contains("page.credential-pressure-combo")
            || pageCodes.contains("page.brand-credential-combo")
        if credentialCollection, impersonationOrPressure, level < .high {
            level = .high
        }

        // A landing page whose visible Visit control points at a look-alike or
        // credential-shaped destination is itself the deception, even if the
        // destination later proves unreachable. Keep this tied to concrete URL
        // evidence, not to the mere presence of an external link.
        let deceptiveVisit = pageCodes.contains("page.misleading-visit-label")
            || pageCodes.contains("page.brand-misdirected-visit")
            || pageCodes.contains("page.concealed-navigation")
        let destinationLookalike = inspection.evidence.contains {
            $0.code.hasPrefix("page.destination.brand.")
                || $0.code.hasPrefix("page.destination.host.")
        }
        if deceptiveVisit, destinationLookalike, level < .high {
            level = .high
        }
        if inspection.hasDestinationCredentialHarvest, level < .high {
            level = .high
        }

        if let prior = result.riskLevel, prior >= .high { level = max(level, prior) }
        updated.riskScore = max(result.riskScore, outcome.score, level == .critical ? 75 : (level == .high ? 50 : 0))
        updated.riskLevel = level
        updated.confidence = outcome.confidence
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: updated.kind)
        return updated
    }

    func applyingRedirectReport(_ result: ScanResult, report: RedirectReport) -> ScanResult {
        var updated = result
        updated.evidence.append(contentsOf: report.evidence)
        updated.checks = (updated.checks ?? []) + report.checks
        updated.checks = (updated.checks ?? []).map { check in
            guard check.name == "Redirect chain" else { return check }
            var updatedCheck = check
            if report.failed {
                updatedCheck.state = .failed
                updatedCheck.detail = "The redirect chain could not be followed."
            } else {
                updatedCheck.state = .passed
                updatedCheck.detail = "\(report.hops.count) redirect(s); final destination \(report.finalURL ?? "unknown")."
            }
            return updatedCheck
        }
        var sources = updated.evidenceSources ?? []
        if !sources.contains("Redirect trace") { sources.append("Redirect trace") }
        updated.evidenceSources = sources
        if let final = report.finalURL, final != updated.analyzedURL {
            updated.limitations.insert("After redirects the final URL is \(final).", at: 0)
        }
        if report.failed {
            updated.limitations.insert("The redirect chain could not be followed. That is an unavailable check, not a clearance.", at: 0)
        }
        for limitation in report.limitations where !updated.limitations.contains(limitation) {
            updated.limitations.append(limitation)
        }
        let outcome = Scoring.score(updated.evidence)
        var level = max(outcome.level, result.riskLevel ?? .low)
        if report.failed, level < .inconclusive { level = .inconclusive }
        updated.riskScore = max(result.riskScore, outcome.score, level == .critical ? 75 : (level == .high ? 50 : 0))
        updated.riskLevel = level
        updated.confidence = outcome.confidence
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: updated.kind)
        return updated
    }

    /// Runs every available live check for a URL and returns one merged result.
    /// `ai` is passed only when AI analysis is explicitly enabled; a successful
    /// connection test alone never reaches this parameter.
    func liveScan(_ url: String, config: ReputationProviderConfig,
                  ai: AIProviderConfig? = nil) async -> ScanResult {
        await liveScanDetailed(url, config: config, ai: ai).result
    }

    /// Same pipeline as `liveScan`, but also returns the page inspection so the
    /// Website Safety Checker can show the exact page it merged rather than running a
    /// second, different fetch.
    func liveScanDetailed(_ url: String, config: ReputationProviderConfig,
                          ai: AIProviderConfig? = nil) async -> (result: ScanResult, inspection: PageInspection?) {
        var result = scanURL(url)
        guard result.status == .complete, let analyzed = result.analyzedURL else { return (result, nil) }
        result = await deepScanReputation(result, config: config)
        let redirects = await RedirectTracer.trace(analyzed)
        result = applyingRedirectReport(result, report: redirects)
        let page = await PageInspector.inspect(url: redirects.finalURL ?? analyzed)
        result = applyingPageInspection(result, inspection: page)
        let domainAge = await DomainInspector.checkAge(redirects.finalURL ?? analyzed)
        result = applyingDomainAgeReport(result, report: domainAge)

        if let ai, ai.analysisEnabled {
            guard ai.isConfigured else {
                result = applyingAIFailure(result, failure: .notConfigured)
                return (result, page)
            }
            let pageAccessible = page.contentAvailable && !page.truncated
            guard pageAccessible else {
                result = applyingAIFailure(result, failure: .misconfigured("the page content was unavailable, so no AI review was made"))
                return (result, page)
            }
            switch await AIAnalyzer.analyze(result: result, inspection: page, config: ai) {
            case .success(let report):
                result = applyingAIAnalysis(result, report: report)
            case .failure(let failure):
                result = applyingAIFailure(result, failure: failure)
            }
        }
        return (result, page)
    }

    /// Merges the shared RDAP domain-age assessment into any live URL result.
    /// A very new domain raises the score as an independent signal, but never
    /// invents content evidence and never turns an unknown age into a clearance.
    func applyingDomainAgeReport(_ result: ScanResult, report: DomainAgeReport) -> ScanResult {
        var updated = result
        for item in report.evidence where !updated.evidence.contains(where: { $0.code == item.code }) {
            updated.evidence.append(item)
        }
        var checks = updated.checks ?? []
        if !checks.contains(where: { $0.name == report.check.name }) {
            checks.append(report.check)
        }
        updated.checks = checks

        var sources = updated.evidenceSources ?? []
        if !sources.contains("RDAP (domain age)") { sources.append("RDAP (domain age)") }
        updated.evidenceSources = sources

        if report.failed {
            updated.skippedChecks.append("Domain registration age (RDAP unavailable)")
            for limitation in report.limitations where !updated.limitations.contains(limitation) {
                updated.limitations.append(limitation)
            }
        } else if report.ageSeconds != nil {
            for limitation in report.limitations where !updated.limitations.contains(limitation) {
                updated.limitations.append(limitation)
            }
        }

        let outcome = Scoring.score(updated.evidence)
        let level = max(updated.riskLevel ?? .low, outcome.level)
        updated.riskLevel = level
        if report.failed && updated.riskLevel == .low { updated.riskLevel = .inconclusive }
        updated.riskScore = max(updated.riskScore, outcome.score,
                                level == .critical ? 75 : (level == .high ? 50 : 0))
        updated.confidence = max(updated.confidence, outcome.confidence)
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: updated.kind)
        return updated
    }

    /// Adds validated AI findings as corroborating evidence. It never removes
    /// deterministic evidence and never lowers the prior level or score.
    func applyingAIAnalysis(_ result: ScanResult, report: AIAnalysisReport) -> ScanResult {
        var updated = result
        updated.aiAnalysis = report
        var checks = updated.checks ?? []
        checks.append(CheckRecord(name: "AI analysis", state: .passed,
                                  detail: "Real request to \(report.provider) (\(report.model)) succeeded in \(Int(report.elapsedMs)) ms; response validated and incorporated."))
        updated.checks = checks
        var sources = updated.evidenceSources ?? []
        let label = "AI analysis (\(report.provider))"
        if !sources.contains(label) { sources.append(label) }
        updated.evidenceSources = sources

        let priorLevel = updated.riskLevel ?? .low
        let priorScore = updated.riskScore
        var added: [Evidence] = []
        switch report.assessment {
        case .phishing:
            added.append(Evidence(
                code: "ai.phishing-assessment",
                title: "AI review: page matches a phishing pattern",
                detail: report.summary + " This is corroborating analysis, not a replacement for the deterministic findings.",
                weight: 14, category: .context))
        case .suspicious:
            added.append(Evidence(
                code: "ai.suspicious-assessment",
                title: "AI review: page is suspicious",
                detail: report.summary,
                weight: 7, category: .context))
        case .none, .unknown:
            // Deliberately no negative weight: AI silence is not a clearance.
            break
        }
        for (index, finding) in report.findings.prefix(3).enumerated() {
            added.append(Evidence(
                code: "ai.finding-\(index + 1)-\(finding.code)",
                title: "AI finding: \(finding.title)",
                detail: finding.detail,
                weight: 4, category: .context))
        }
        updated.evidence.append(contentsOf: added)
        for limitation in report.limitations {
            let entry = "AI review limitation: \(limitation)"
            if !updated.limitations.contains(entry) { updated.limitations.append(entry) }
        }
        if report.assessment == .none, priorLevel >= .high {
            updated.limitations.append("The AI review did not add phishing evidence, but the deterministic findings were retained and were not weakened.")
        }

        let outcome = Scoring.score(updated.evidence)
        var level = outcome.level
        if level < priorLevel { level = priorLevel }
        // AI can corroborate and raise a page into the caution band, but a single
        // model opinion never forces HIGH on its own.
        if report.assessment == .phishing, level < .medium { level = .medium }
        updated.riskLevel = level
        updated.riskScore = max(priorScore, outcome.score,
                                level == .critical ? 75 : (level == .high ? 50 : 0))
        updated.confidence = max(updated.confidence, report.confidence)
        updated.recommendedAction = Scoring.recommendedAction(level: level, kind: updated.kind)
        return updated
    }

    func applyingAIFailure(_ result: ScanResult, failure: AIProviderFailure) -> ScanResult {
        var updated = result
        var checks = updated.checks ?? []
        let state: CheckRecord.State
        switch failure {
        case .notConfigured:
            state = .skipped
        case .rateLimited, .quotaExhausted, .timeout, .unreachable, .serverError:
            state = .unavailable
        case .invalidAPIKey, .permissionDenied, .modelUnavailable,
             .unsupportedOperation, .noCompatibleModels:
            state = .failed
        default:
            state = .failed
        }
        let detail = failure.errorDescription ?? "Unknown AI error"
        checks.append(CheckRecord(name: "AI analysis", state: state, detail: detail))
        updated.checks = checks
        let limitation = "AI analysis did not run: \(detail) The deterministic result stands."
        if !updated.limitations.contains(limitation) { updated.limitations.append(limitation) }
        return updated
    }
}

// MARK: - Optional AI explanation (never a verdict source)

public enum AIExplainer {
    /// Asks the configured model to explain the evidence. This request does not
    /// change the score, level or recommended action.
    public static func explain(_ result: ScanResult, config: AIProviderConfig) async -> (text: String?, error: String?) {
        guard config.isConfigured else {
            return (nil, "AI explanation is not configured. Add a provider in Settings › AI.")
        }
        let evidenceText = result.evidence.prefix(20).map {
            "- [\($0.weight >= 0 ? "+" : "")\($0.weight)] \($0.title): \($0.detail)"
        }.joined(separator: "\n")
        let limitations = result.limitations.joined(separator: "\n")
        let prompt = """
        You are explaining a ScamShield result to a non-expert. Use ONLY the evidence and limitations below.
        Do not invent findings, do not claim you visited the page, and do not change the verdict.
        Verdict: \(result.displayVerdict), score \(result.riskScore)/100, confidence \(result.confidence.rawValue).
        Evidence:
        \(evidenceText)
        Limitations:
        \(limitations)
        Write 3 short bullet points: what was observed, what it does and does not prove, and one safe next step.
        """
        switch await AIProviderClient.completeWithFallback(
            system: "You explain security evidence accurately and never fabricate scan results.",
            user: prompt, config: config, expectJSON: false) {
        case .success(let completion): return (completion.text, nil)
        case .failure(let error): return (nil, error.errorDescription ?? "Unknown AI error")
        }
    }
}
