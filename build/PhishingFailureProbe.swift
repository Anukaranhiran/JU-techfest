import Foundation
import ScamShieldCore

// Temporary verification harness: existing network guard only; no saved keys, AI,
// provider calls, credentials, browser, script execution or form submission.
@main struct PhishingFailureProbe {
    static func main() async throws {
        let raw = CommandLine.arguments[1]
        let engine = ScanEngine()
        let initial = engine.scanURL(raw)
        var merged = await engine.deepScanReputation(initial, config: .init(urlhausEnabled: false))
        let redirects = await RedirectTracer.trace(raw)
        merged = engine.applyingRedirectReport(merged, report: redirects)
        let page = await PageInspector.inspect(url: redirects.finalURL ?? raw)
        merged = engine.applyingPageInspection(merged, inspection: page)
        struct Report: Encodable {
            let date: Date
            let local: ScanResult
            let final: ScanResult
            let verdict: String
            let httpStatus: Int?
            let finalURL: String?
            let redirects: [RedirectHop]
            let title: String?
            let staticText: String
            let forms: [InspectedForm]
            let scriptPatterns: [String]
            let bodyBytes: Int
            let truncated: Bool
            let ai: String
            let reputation: String
        }
        let report = Report(date: Date(), local: initial, final: merged, verdict: merged.displayVerdict,
                            httpStatus: page.httpStatus, finalURL: page.finalURL, redirects: redirects.hops,
                            title: page.title, staticText: page.textExcerpt, forms: page.forms,
                            scriptPatterns: page.suspiciousScriptPatterns, bodyBytes: page.bodyBytes,
                            truncated: page.truncated, ai: "Not requested", reputation: "All providers explicitly disabled for local detection verification")
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)
        if CommandLine.arguments.count > 2 { try data.write(to: URL(fileURLWithPath: CommandLine.arguments[2])) }
        print(String(decoding: data, as: UTF8.self))
    }
}
