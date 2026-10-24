import AppKit
import CoreServices
import Foundation
import ScamShieldCore

// ScamShield command line tool: deterministic scanning for tests and CI.
// Exit codes: 0 low, 1 medium, 2 high/critical, 3 unverified/failed, 64 usage.

func printUsage() {
    let usage = """
    scamshieldctl — offline scanner for ScamShield

    USAGE
      scamshieldctl scan-url <url> [--live] [--json]
      scamshieldctl scan-text <text> [--live] [--json]
      scamshieldctl scan-email <file> [--live] [--json]
      scamshieldctl eval [--json]
      scamshieldctl selftest

    --live runs the bounded live pipeline: configured reputation providers,
    redirect tracing and page inspection. Without it the scanner is offline
    and deterministic (used by tests).

    Exit codes: 0 low, 1 medium, 2 high/critical, 3 unverified, 64 usage error.
    """
    print(usage)
}

func exitCode(for result: ScanResult) -> Int32 {
    guard result.status == .complete, let level = result.riskLevel else { return 3 }
    switch level {
    case .low: return 0
    case .inconclusive, .medium: return 1
    case .high, .critical: return 2
    }
}

func printHuman(_ result: ScanResult) {
    print("verdict:   \(result.displayVerdict)")
    if let level = result.riskLevel {
        print("risk:      \(result.riskScore)/100 (\(level.title))")
    } else {
        print("risk:      unknown — scan status \(result.status.rawValue)")
    }
    print("confidence:\(result.confidence.title)")
    if let url = result.analyzedURL { print("url:       \(url)") }
    if !result.evidence.isEmpty {
        print("evidence:")
        for item in result.evidence.sorted(by: { abs($0.weight) > abs($1.weight) }) {
            let sign = item.weight >= 0 ? "+" : ""
            print("  [\(sign)\(item.weight)] \(item.title) — \(item.detail)")
        }
    }
    if let checks = result.checks, !checks.isEmpty {
        print("checks:")
        for check in checks {
            print("  [\(check.state.rawValue)] \(check.name) — \(check.detail)")
        }
    }
    if let sources = result.evidenceSources, !sources.isEmpty {
        print("sources:   \(sources.joined(separator: ", "))")
    }
    if let ai = result.aiAnalysis {
        print("ai:        \(ai.provider) · \(ai.model) · \(ai.assessment.rawValue) (\(ai.confidence.rawValue) confidence)")
        print("ai summary:\(ai.summary)")
        for finding in ai.findings {
            print("  AI: \(finding.title) — \(finding.detail)")
        }
    }
    if !result.recommendedAction.isEmpty {
        print("action:    \(result.recommendedAction)")
    }
    for limitation in result.limitations {
        print("limit:     \(limitation)")
    }
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    printUsage()
    exit(64)
}
let wantsJSON = args.contains("--json")
let engine = ScanEngine()

var result: ScanResult?
var outputFile: URL?

switch command {
case "scan-url":
    guard let url = args.dropFirst().first(where: { !$0.hasPrefix("--") }) else {
        printUsage(); exit(64)
    }
    if args.contains("--live") {
        // Explicit opt-in for terminal verification. Uses the same safe pipeline and
        // the provider keys already configured in the app.
        let settings = SettingsStore().settings
        let config = settings.reputation
        let ai = settings.aiConfig
        let semaphore = DispatchSemaphore(value: 0)
        var live: ScanResult?
        Task {
            live = await engine.liveScan(url, config: config,
                                         ai: ai.analysisEnabled ? ai : nil)
            semaphore.signal()
        }
        semaphore.wait()
        result = live
    } else {
        result = engine.scanURL(url)
    }

case "scan-text":
    let parts = args.dropFirst().filter { !$0.hasPrefix("--") }
    let text = parts.joined(separator: " ")
    guard !text.isEmpty else { printUsage(); exit(64) }
    if args.contains("--live") {
        let settings = SettingsStore().settings
        let config = settings.reputation
        let ai = settings.aiConfig
        let semaphore = DispatchSemaphore(value: 0)
        var live: ScanResult?
        Task {
            live = await engine.liveScanMessage(text, config: config,
                                                ai: ai.analysisEnabled ? ai : nil)
            semaphore.signal()
        }
        semaphore.wait()
        result = live
    } else {
        result = engine.scanMessage(text)
    }

case "scan-email":
    guard let path = args.dropFirst().first(where: { !$0.hasPrefix("--") }) else {
        printUsage(); exit(64)
    }
    guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        exit(64)
    }
    if args.contains("--live") {
        let settings = SettingsStore().settings
        let config = settings.reputation
        let ai = settings.aiConfig
        let semaphore = DispatchSemaphore(value: 0)
        var live: ScanResult?
        Task {
            live = await engine.liveScanEmail(content, config: config,
                                              ai: ai.analysisEnabled ? ai : nil)
            semaphore.signal()
        }
        semaphore.wait()
        result = live
    } else {
        result = engine.scanEmail(content)
    }

case "eval":
    let run = EvaluationRunner(engine: engine).runBuiltIn()
    if wantsJSON {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(run), let text = String(data: data, encoding: .utf8) {
            print(text)
        }
    } else {
        print("fixtures: \(run.total)  detected: \(run.truePositives + run.trueNegatives)/\(run.total)")
        print("precision: \(String(format: "%.2f", run.precision))  recall: \(String(format: "%.2f", run.recall))  f1: \(String(format: "%.2f", run.f1))")
        print("false positives: \(run.falsePositives)  false negatives: \(run.falseNegatives)")
        for failure in run.failures {
            print("  FAIL \(failure.fixtureID): expected \(failure.expected), got \(failure.actual) — \(failure.detail)")
        }
    }
    exit(run.falsePositives == 0 && run.falseNegatives == 0 ? 0 : 1)

case "handler-status":
    func handler(_ scheme: String) -> String {
        LSCopyDefaultHandlerForURLScheme(scheme as CFString)?.takeRetainedValue() as String? ?? "<none>"
    }
    print("http  -> \(handler("http"))")
    print("https -> \(handler("https"))")
    if let probe = URL(string: "https://example.com") {
        print("\nbrowsers registered with LaunchServices:")
        for url in NSWorkspace.shared.urlsForApplications(toOpen: probe) {
            let bundle = Bundle(url: url)
            let id = bundle?.bundleIdentifier ?? "?"
            let name = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? url.deletingPathExtension().lastPathComponent
            print("  \(id)  \(name)  \(url.path)")
        }
    }
    exit(0)

case "selftest":
    let benign = engine.scanURL("https://www.apple.com/support/")
    let bad = engine.scanURL("https://appleid-apple.com-verify-account.tk/login/confirm")
    var ok = true
    if benign.riskLevel != .low { print("selftest FAIL: expected benign URL to be low risk, got \(benign.displayVerdict)"); ok = false }
    if bad.riskLevel ?? .low < .high { print("selftest FAIL: expected phishing fixture to be high+, got \(bad.displayVerdict)"); ok = false }
    print(ok ? "selftest: PASS" : "selftest: FAIL")
    exit(ok ? 0 : 1)

case "history-path":
    outputFile = HistoryStore.defaultFileURL
    print(outputFile?.path ?? "unknown")

case "-h", "--help", "help":
    printUsage()
    exit(0)

default:
    printUsage()
    exit(64)
}

if let result {
    if wantsJSON {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) else {
            FileHandle.standardError.write(Data("failed to encode result\n".utf8))
            exit(3)
        }
        print(text)
    } else {
        printHuman(result)
    }
    exit(exitCode(for: result))
}
