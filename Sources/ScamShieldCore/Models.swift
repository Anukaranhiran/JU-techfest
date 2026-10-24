import Foundation

// MARK: - Risk vocabulary

/// Risk bands used by every surface (decision window, dashboard, history, API).
public enum RiskLevel: String, Codable, CaseIterable, Sendable, Comparable {
    case low
    /// The checks that could prove safety did not run, were unavailable, or returned
    /// conflicting data. A missing result is never a clearance.
    case inconclusive
    case medium
    case high
    case critical

    public var rank: Int {
        switch self {
        case .low: return 0
        case .inconclusive: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public var title: String {
        switch self {
        case .low: return "Low risk"
        case .inconclusive: return "Inconclusive"
        case .medium: return "Medium risk"
        case .high: return "High risk"
        case .critical: return "Critical risk"
        }
    }

    /// High, critical, and inconclusive results must never navigate without an explicit bypass.
    /// Inconclusive is included because "we could not verify this" is not permission to open.
    public var requiresExplicitBypass: Bool { rank >= RiskLevel.inconclusive.rank }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.rank < rhs.rank }

    public static func band(forScore score: Int) -> RiskLevel {
        switch score {
        case ..<20: return .low
        case 20..<50: return .medium
        case 50..<75: return .high
        default: return .critical
        }
    }
}

/// Confidence reflects *how much* evidence exists, not how scary it is.
/// A scan with three weak heuristics is medium risk / low confidence; a scan that
/// matched an official domain exactly is low risk / high confidence.
public enum Confidence: String, Codable, Sendable, Comparable {
    case low, medium, high

    public static func < (lhs: Confidence, rhs: Confidence) -> Bool { lhs.rank < rhs.rank }

    public var title: String {
        switch self {
        case .low: return "Low confidence"
        case .medium: return "Medium confidence"
        case .high: return "High confidence"
        }
    }
}

/// Whether the deterministic engine actually finished.
/// `complete` is the only status that may be described as verified. A failed or
/// skipped scan always surfaces as UNVERIFIED — never as SAFE.
public enum ScanStatus: String, Codable, Sendable {
    case complete
    case failed
    case unsupported

    public var isVerified: Bool { self == .complete }
}

public enum ScanKind: String, Codable, Sendable, CaseIterable {
    case url
    case message
    case email
    case qr
    case screenshot

    public var title: String {
        switch self {
        case .url: return "Link"
        case .message: return "Message"
        case .email: return "Email"
        case .qr: return "QR code"
        case .screenshot: return "Screenshot"
        }
    }
}

// MARK: - Evidence

public struct Evidence: Codable, Hashable, Sendable, Identifiable {
    public enum Category: String, Codable, Sendable {
        case scheme
        case structure
        case domain
        case brand
        case transport
        case redirect
        case content
        case reputation
        case context

        public var title: String {
            switch self {
            case .scheme: return "Scheme"
            case .structure: return "URL structure"
            case .domain: return "Domain"
            case .brand: return "Brand impersonation"
            case .transport: return "Transport"
            case .redirect: return "Redirect"
            case .content: return "Content"
            case .reputation: return "Reputation"
            case .context: return "Context"
            }
        }
    }

    public var code: String
    public var title: String
    public var detail: String
    /// Positive = raises risk, negative = lowers risk. Range roughly -40...40.
    public var weight: Int
    public var category: Category

    public var id: String { code + "|" + detail }

    public init(code: String, title: String, detail: String, weight: Int, category: Category) {
        self.code = code
        self.title = title
        self.detail = detail
        self.weight = weight
        self.category = category
    }
}

// MARK: - Checks

/// One named check that ran, or did not run, during a scan. This is what lets the UI
/// say "reputation unavailable" instead of silently folding it into a safe verdict.
public struct CheckRecord: Codable, Hashable, Sendable, Identifiable {
    public enum State: String, Codable, Sendable {
        case passed
        case failed
        case skipped
        case unavailable
    }

    public var name: String
    public var state: State
    public var detail: String

    public var id: String { name + "|" + state.rawValue }

    public init(name: String, state: State, detail: String) {
        self.name = name
        self.state = state
        self.detail = detail
    }
}

// MARK: - Scan result

public struct ScanResult: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var kind: ScanKind
    /// Exactly what was submitted, truncated for storage hygiene.
    public var input: String
    /// The URL that was actually analysed, when one could be extracted.
    public var analyzedURL: String?
    public var host: String?
    public var registrableDomain: String?
    public var riskScore: Int
    public var riskLevel: RiskLevel?
    public var status: ScanStatus
    public var confidence: Confidence
    public var evidence: [Evidence]
    public var limitations: [String]
    public var recommendedAction: String
    /// Notes about optional checks that did not run (e.g. external reputation).
    public var skippedChecks: [String]
    /// Structured record of every check, including the ones that did not run.
    /// Optional so history written by older builds still decodes.
    public var checks: [CheckRecord]?
    /// Providers whose data contributed to this result (e.g. "VirusTotal").
    public var evidenceSources: [String]?
    /// Present only when a real AI request succeeded and its validated findings were
    /// incorporated into this scan. Optional so older history still decodes.
    public var aiAnalysis: AIAnalysisReport?
    public var createdAt: Date
    public var durationMs: Double

    public init(
        id: UUID = UUID(),
        kind: ScanKind,
        input: String,
        analyzedURL: String? = nil,
        host: String? = nil,
        registrableDomain: String? = nil,
        riskScore: Int = 0,
        riskLevel: RiskLevel? = nil,
        status: ScanStatus = .complete,
        confidence: Confidence = .medium,
        evidence: [Evidence] = [],
        limitations: [String] = [],
        recommendedAction: String = "",
        skippedChecks: [String] = [],
        checks: [CheckRecord]? = nil,
        evidenceSources: [String]? = nil,
        aiAnalysis: AIAnalysisReport? = nil,
        createdAt: Date = Date(),
        durationMs: Double = 0
    ) {
        self.id = id
        self.kind = kind
        self.input = input
        self.analyzedURL = analyzedURL
        self.host = host
        self.registrableDomain = registrableDomain
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.status = status
        self.confidence = confidence
        self.evidence = evidence
        self.limitations = limitations
        self.recommendedAction = recommendedAction
        self.skippedChecks = skippedChecks
        self.checks = checks
        self.evidenceSources = evidenceSources
        self.aiAnalysis = aiAnalysis
        self.createdAt = createdAt
        self.durationMs = durationMs
    }

    /// Positive-weight evidence, strongest first.
    public var topEvidence: [Evidence] {
        evidence.filter { $0.weight > 0 }.sorted { $0.weight > $1.weight }
    }

    public var protectiveEvidence: [Evidence] {
        evidence.filter { $0.weight < 0 }.sorted { $0.weight < $1.weight }
    }

    /// The badge the UI must show. Deliberately computed: an incomplete scan can
    /// never render as a safe verdict.
    public var displayVerdict: String {
        guard status == .complete, let level = riskLevel else { return "UNVERIFIED" }
        switch level {
        case .low: return "LOW RISK"
        case .inconclusive: return "INCONCLUSIVE"
        case .medium: return "CAUTION"
        case .high: return "HIGH RISK"
        case .critical: return "CRITICAL"
        }
    }

    public var isVerified: Bool { status == .complete && riskLevel != nil }
}

// MARK: - Recorded user decisions

public enum ActionKind: String, Codable, Sendable, CaseIterable {
    case autoAllowed
    case openedInBrowser
    case openedAnyway
    case cancelled
    case allowlisted
    case blocked
    case scanOnly
    case handoffFailed

    public var title: String {
        switch self {
        case .autoAllowed: return "Auto-allowed"
        case .openedInBrowser: return "Opened in browser"
        case .openedAnyway: return "Opened after bypass"
        case .cancelled: return "Cancelled by user"
        case .allowlisted: return "Allowlisted domain"
        case .blocked: return "Blocked"
        case .scanOnly: return "Scanned only"
        case .handoffFailed: return "Browser handoff failed"
        }
    }

    /// True when the destination was deliberately released to a browser.
    public var openedDestination: Bool {
        switch self {
        case .autoAllowed, .openedInBrowser, .openedAnyway, .allowlisted: return true
        default: return false
        }
    }
}

public struct ActionRecord: Codable, Sendable, Hashable {
    public var action: ActionKind
    public var browserName: String?
    public var browserBundleID: String?
    public var note: String?
    public var at: Date

    public init(action: ActionKind, browserName: String? = nil, browserBundleID: String? = nil, note: String? = nil, at: Date = Date()) {
        self.action = action
        self.browserName = browserName
        self.browserBundleID = browserBundleID
        self.note = note
        self.at = at
    }
}

/// One row of local history: a scan plus the decision that followed it.
public struct HistoryEntry: Codable, Sendable, Identifiable, Hashable {
    public var scan: ScanResult
    public var action: ActionRecord?
    /// Where the URL came from, when known (e.g. "LaunchServices", "Chrome extension").
    public var source: String?

    public var id: UUID { scan.id }

    public init(scan: ScanResult, action: ActionRecord? = nil, source: String? = nil) {
        self.scan = scan
        self.action = action
        self.source = source
    }
}

// MARK: - Errors

public enum ScamShieldError: LocalizedError, Sendable {
    case invalidURL(String)
    case unsupportedScheme(String)
    case mediaDecodeFailed(String)
    case storage(String)
    case externalService(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let s): return "Not a valid web URL: \(s)"
        case .unsupportedScheme(let s): return "Unsupported URL scheme: \(s)"
        case .mediaDecodeFailed(let s): return "Could not decode \(s)"
        case .storage(let s): return "Storage error: \(s)"
        case .externalService(let s): return "External service error: \(s)"
        }
    }
}
