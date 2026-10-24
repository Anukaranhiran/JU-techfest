import Foundation

// MARK: - Paths

public enum StorePaths {
    public static let directoryName = "ScamShield"

    public static var supportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var historyFile: URL { supportDirectory.appendingPathComponent("history.jsonl") }
    public static var settingsFile: URL { supportDirectory.appendingPathComponent("settings.json") }
    public static var allowlistFile: URL { supportDirectory.appendingPathComponent("allowlist.json") }
    public static var tokenFile: URL { supportDirectory.appendingPathComponent("api-token") }
    public static var extensionHeartbeatsFile: URL { supportDirectory.appendingPathComponent("extension-heartbeats.json") }
}

// MARK: - Settings

public struct ScanSettings: Codable, Sendable, Equatable {
    /// When false (default) every intercepted link shows the decision window.
    public var autoAllowLowRisk: Bool = false
    /// Explicit user-chosen handoff browser. nil = ask each time / system browser.
    public var chosenBrowserBundleID: String? = "com.operasoftware.OperaGX"
    /// The browser that was the system default before ScamShield took over, for restore.
    public var previousDefaultBundleID: String?
    public var launchAtLogin: Bool = false
    public var interceptionEnabled: Bool = true
    public var externalReputationEnabled: Bool = false
    public var localAPIEnabled: Bool = true
    public var apiPort: Int = 47613
    /// Days to keep scan history locally. 0 = keep forever.
    public var retentionDays: Int = 90
    public var showAdvancedEvidence: Bool = true
    public var lastSeenVersion: String = ""

    // Optional integrations. These are optional in storage so settings written by an
    // older build still decode without losing the chosen browser and history settings.
    /// Master switch for outbound checks (reputation, page inspection, DNS). Off by default.
    public var liveChecksEnabled: Bool?
    /// Run live checks before showing the interception decision window.
    public var deepScanOnIntercept: Bool?
    public var virusTotalAPIKey: String?
    public var safeBrowsingAPIKey: String?
    public var hibpAPIKey: String?
    public var urlhausEnabled: Bool?
    /// Optional AI provider. `aiEnabled` controls explanatory commentary only;
    /// `aiAnalysisEnabled` is a separate, explicit opt-in for scans.
    public var aiEnabled: Bool?
    public var aiAnalysisEnabled: Bool?
    /// "gemini" or "openai" (OpenAI-compatible).
    public var aiProvider: String?
    public var aiBaseURL: String?
    /// Model id selected by discovery. Never assumed; it has been probed.
    public var aiModel: String?
    /// Models the key could actually see at the last discovery. Metadata only.
    public var aiDiscoveredModels: [GeminiModel]?
    public var aiDiscoveryTimestamp: Date?
    public var aiModelVerifiedAt: Date?
    public var aiLastSuccessfulTestAt: Date?
    /// SHA-256 marker used only to invalidate a cached selection when the key changes.
    public var aiKeyFingerprint: String?
    /// Legacy plaintext fields. Read once for migration, then removed from disk.
    /// New values live in the macOS Keychain.
    public var aiAPIKey: String?

    public init() {}

    /// Safe, bounded live inspection is on by default for manual scans. It can be
    /// switched off, and interception-time deep scanning remains a separate opt-in.
    public var liveChecks: Bool { liveChecksEnabled ?? true }
    public var deepIntercept: Bool { deepScanOnIntercept ?? false }
    public var aiAnalysisOn: Bool { aiAnalysisEnabled ?? false }

    /// Keys are read from the login Keychain. The plaintext fields above exist only
    /// so settings written by an older build can be migrated by `SettingsStore`.
    public var virusTotalKey: String { KeychainStore.get(SecretAccount.virusTotal) ?? "" }
    public var safeBrowsingKey: String { KeychainStore.get(SecretAccount.safeBrowsing) ?? "" }
    public var hibpKey: String { KeychainStore.get(SecretAccount.hibp) ?? "" }
    public var aiKey: String { KeychainStore.get(SecretAccount.ai) ?? "" }

    public var aiConfig: AIProviderConfig {
        let kind = AIProviderKind(rawValue: aiProvider ?? "") ?? .openAICompatible
        return AIProviderConfig(enabled: aiEnabled ?? false,
                                analysisEnabled: aiAnalysisOn,
                                provider: kind,
                                baseURL: aiBaseURL ?? "",
                                model: aiModel ?? "",
                                apiKey: aiKey,
                                discoveredModels: aiDiscoveredModels ?? [],
                                allowModelFallback: true)
    }

    public var reputation: ReputationProviderConfig {
        ReputationProviderConfig(virusTotalAPIKey: virusTotalKey,
                                 safeBrowsingAPIKey: safeBrowsingKey,
                                 urlhausEnabled: urlhausEnabled ?? true)
    }
}

public final class SettingsStore {
    private let fileURL: URL
    private let lock = NSLock()
    private var cache: ScanSettings

    public init(fileURL: URL = StorePaths.settingsFile) {
        self.fileURL = fileURL
        self.cache = ScanSettings()
        load()
    }

    public var settings: ScanSettings {
        lock.lock(); defer { lock.unlock() }
        return cache
    }

    public func update(_ mutate: (inout ScanSettings) -> Void) {
        lock.lock()
        mutate(&cache)
        let snapshot = cache
        lock.unlock()
        save(snapshot)
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              var decoded = try? JSONDecoder().decode(ScanSettings.self, from: data) else { return }

        // Migrate keys written by older builds into the Keychain and remove them from
        // the JSON file. This runs even when the Keychain write fails so a key is not
        // left in plaintext indefinitely.
        var migrated = false
        func migrate(_ value: String?, to account: String) {
            guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
            KeychainStore.set(value, for: account)
            migrated = true
        }
        migrate(decoded.virusTotalAPIKey, to: SecretAccount.virusTotal)
        migrate(decoded.safeBrowsingAPIKey, to: SecretAccount.safeBrowsing)
        migrate(decoded.hibpAPIKey, to: SecretAccount.hibp)
        migrate(decoded.aiAPIKey, to: SecretAccount.ai)
        decoded.virusTotalAPIKey = nil
        decoded.safeBrowsingAPIKey = nil
        decoded.hibpAPIKey = nil
        decoded.aiAPIKey = nil
        cache = decoded
        if migrated { save(decoded) }
    }

    private func save(_ value: ScanSettings) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}

// MARK: - Allowlist

public struct AllowlistEntry: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var domain: String
    public var addedAt: Date
    public var expiresAt: Date?
    public var note: String?

    public init(id: UUID = UUID(), domain: String, addedAt: Date = Date(), expiresAt: Date? = nil, note: String? = nil) {
        self.id = id
        self.domain = domain
        self.addedAt = addedAt
        self.expiresAt = expiresAt
        self.note = note
    }

    public var isActive: Bool {
        guard let expiresAt else { return true }
        return expiresAt > Date()
    }
}

public final class AllowlistStore {
    private let fileURL: URL
    private let lock = NSLock()
    private var entries: [AllowlistEntry]

    public init(fileURL: URL = StorePaths.allowlistFile) {
        self.fileURL = fileURL
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder().decode([AllowlistEntry].self, from: data) {
            entries = decoded
        } else {
            entries = []
        }
    }

    public var all: [AllowlistEntry] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }

    public func isAllowed(host: String) -> Bool {
        let normalized = DomainUtils.normalizeHost(host)
        lock.lock(); defer { lock.unlock() }
        return entries.contains { entry in
            entry.isActive && (normalized == entry.domain || normalized.hasSuffix("." + entry.domain))
        }
    }

    public func add(domain: String, durationDays: Int = 30, note: String? = nil) {
        let normalized = DomainUtils.normalizeHost(domain)
        guard !normalized.isEmpty else { return }
        lock.lock()
        entries.removeAll { $0.domain == normalized }
        entries.append(AllowlistEntry(domain: normalized,
                                      expiresAt: durationDays == 0 ? nil : Date().addingTimeInterval(Double(durationDays) * 86400),
                                      note: note))
        let snapshot = entries
        lock.unlock()
        persist(snapshot)
    }

    public func remove(id: UUID) {
        lock.lock()
        entries.removeAll { $0.id == id }
        let snapshot = entries
        lock.unlock()
        persist(snapshot)
    }

    public func remove(domain: String) {
        lock.lock()
        entries.removeAll { $0.domain == DomainUtils.normalizeHost(domain) }
        let snapshot = entries
        lock.unlock()
        persist(snapshot)
    }

    public func clear() {
        lock.lock(); entries = []; lock.unlock()
        persist([])
    }

    private func persist(_ value: [AllowlistEntry]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(value) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }
}

// MARK: - History

public struct HistoryFilter: Sendable, Equatable {
    public var levels: Set<RiskLevel> = []
    public var kinds: Set<ScanKind> = []
    public var actions: Set<ActionKind> = []
    public var search: String = ""
    public var since: Date?
    public var onlyWithActions = false
    public var onlyBlocked = false

    public init() {}

    public func matches(_ entry: HistoryEntry) -> Bool {
        if !levels.isEmpty {
            guard let level = entry.scan.riskLevel, levels.contains(level) else { return false }
        }
        if !kinds.isEmpty, !kinds.contains(entry.scan.kind) { return false }
        if !actions.isEmpty {
            guard let action = entry.action?.action, actions.contains(action) else { return false }
        }
        if onlyWithActions && entry.action == nil { return false }
        if onlyBlocked, entry.action?.action != .cancelled, entry.action?.action != .blocked { return false }
        if let since, entry.scan.createdAt < since { return false }
        if !search.isEmpty {
            let needle = search.lowercased()
            let haystack = [entry.scan.input, entry.scan.analyzedURL ?? "", entry.scan.host ?? "", entry.action?.note ?? ""]
                .joined(separator: " ").lowercased()
            if !haystack.contains(needle) { return false }
        }
        return true
    }
}

public final class HistoryStore {
    public static var defaultFileURL: URL? { StorePaths.historyFile }

    private let fileURL: URL
    private let lock = NSLock()
    private var cache: [HistoryEntry]
    private let limit = 5000

    public init(fileURL: URL = StorePaths.historyFile) {
        self.fileURL = fileURL
        self.cache = []
        load()
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return cache.count
    }

    public func all() -> [HistoryEntry] {
        lock.lock(); defer { lock.unlock() }
        return cache
    }

    public func entries(filter: HistoryFilter, limit: Int = 500) -> [HistoryEntry] {
        lock.lock()
        let snapshot = cache
        lock.unlock()
        return snapshot.filter { filter.matches($0) }
            .sorted { $0.scan.createdAt > $1.scan.createdAt }
            .prefix(limit)
            .map { $0 }
    }

    @discardableResult
    public func append(_ entry: HistoryEntry, retentionDays: Int = 0) -> HistoryEntry {
        lock.lock()
        cache.append(entry)
        if cache.count > limit { cache.removeFirst(cache.count - limit) }
        if retentionDays > 0 {
            let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86400)
            cache.removeAll { $0.scan.createdAt < cutoff }
        }
        let snapshot = cache
        lock.unlock()
        rewrite(snapshot)
        return entry
    }

    public func updateAction(for id: UUID, action: ActionRecord) {
        lock.lock()
        if let idx = cache.firstIndex(where: { $0.scan.id == id }) {
            cache[idx].action = action
        }
        let snapshot = cache
        lock.unlock()
        rewrite(snapshot)
    }

    public func clear() {
        lock.lock(); cache = []; lock.unlock()
        rewrite([])
    }

    public func delete(id: UUID) {
        lock.lock()
        cache.removeAll { $0.scan.id == id }
        let snapshot = cache
        lock.unlock()
        rewrite(snapshot)
    }

    // MARK: Statistics

    public struct Stats: Sendable {
        public var total: Int
        public var blocked: Int
        public var opened: Int
        public var bypassed: Int
        public var byLevel: [RiskLevel: Int]
    }

    public func stats() -> Stats {
        let snapshot = all()
        var byLevel: [RiskLevel: Int] = [:]
        var blocked = 0, opened = 0, bypassed = 0
        for entry in snapshot {
            if let level = entry.scan.riskLevel { byLevel[level, default: 0] += 1 }
            switch entry.action?.action {
            case .cancelled, .blocked: blocked += 1
            case .openedInBrowser, .autoAllowed, .allowlisted: opened += 1
            case .openedAnyway: bypassed += 1; opened += 1
            default: break
            }
        }
        return Stats(total: snapshot.count, blocked: blocked, opened: opened, bypassed: bypassed, byLevel: byLevel)
    }

    // MARK: Export

    public enum ExportFormat: String, Sendable, CaseIterable {
        case json, csv, markdown
    }

    public func export(format: ExportFormat, entries: [HistoryEntry]) throws -> Data {
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            return try encoder.encode(entries)
        case .csv:
            var rows = ["timestamp,kind,verdict,score,confidence,url,host,action,browser,source,top_evidence"]
            let formatter = ISO8601DateFormatter()
            for entry in entries {
                let fields = [
                    formatter.string(from: entry.scan.createdAt),
                    entry.scan.kind.rawValue,
                    entry.scan.displayVerdict,
                    "\(entry.scan.riskScore)",
                    entry.scan.confidence.rawValue,
                    entry.scan.analyzedURL ?? entry.scan.input,
                    entry.scan.host ?? "",
                    entry.action?.action.rawValue ?? "",
                    entry.action?.browserName ?? "",
                    entry.source ?? "",
                    entry.scan.topEvidence.first?.title ?? "",
                ]
                rows.append(fields.map(Self.csvEscape).joined(separator: ","))
            }
            return Data(rows.joined(separator: "\n").utf8)
        case .markdown:
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .short
            var out = "# ScamShield report\n\nGenerated \(formatter.string(from: Date()))\n\n"
            out += "| Time | Kind | Verdict | Score | Host | Action |\n|---|---|---|---|---|---|\n"
            for entry in entries {
                let host = entry.scan.host ?? entry.scan.analyzedURL ?? "—"
                out += "| \(formatter.string(from: entry.scan.createdAt)) | \(entry.scan.kind.title) | \(entry.scan.displayVerdict) | \(entry.scan.riskScore) | `\(host)` | \(entry.action?.action.title ?? "—") |\n"
            }
            out += "\n## Evidence detail\n"
            for entry in entries.prefix(200) {
                out += "\n### \(entry.scan.analyzedURL ?? entry.scan.input)\n"
                out += "- Verdict: **\(entry.scan.displayVerdict)** (\(entry.scan.riskScore)/100, \(entry.scan.confidence.title))\n"
                if let action = entry.action {
                    out += "- User action: \(action.action.title)\(action.browserName.map { " in \($0)" } ?? "")\n"
                }
                for item in entry.scan.topEvidence.prefix(5) {
                    out += "- (\(item.weight >= 0 ? "+" : "")\(item.weight)) \(item.title): \(item.detail)\n"
                }
            }
            return Data(out.utf8)
        }
    }

    static func csvEscape(_ value: String) -> String {
        let cleaned = value.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(cleaned)\""
    }

    // MARK: Persistence

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let text = String(data: data, encoding: .utf8) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var loaded: [HistoryEntry] = []
        for line in text.split(separator: "\n") where !line.isEmpty {
            if let entry = try? decoder.decode(HistoryEntry.self, from: Data(line.utf8)) {
                loaded.append(entry)
            }
        }
        cache = Array(loaded.suffix(limit))
    }

    private func rewrite(_ entries: [HistoryEntry]) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        var lines: [String] = []
        lines.reserveCapacity(entries.count)
        for entry in entries {
            if let data = try? encoder.encode(entry), let text = String(data: data, encoding: .utf8) {
                lines.append(text)
            }
        }
        let payload = lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")
        try? Data(payload.utf8).write(to: fileURL, options: .atomic)
    }
}

// MARK: - Extension heartbeats

public struct ExtensionHeartbeat: Codable, Sendable, Identifiable, Hashable {
    public var id: String { browser }
    public var browser: String
    public var version: String
    public var lastSeen: Date

    public init(browser: String, version: String, lastSeen: Date = Date()) {
        self.browser = browser
        self.version = version
        self.lastSeen = lastSeen
    }

    public var isRecent: Bool { Date().timeIntervalSince(lastSeen) < 300 }
}

public final class HeartbeatStore {
    private let fileURL: URL
    private let lock = NSLock()
    private var entries: [ExtensionHeartbeat]

    public init(fileURL: URL = StorePaths.extensionHeartbeatsFile) {
        self.fileURL = fileURL
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder().decode([ExtensionHeartbeat].self, from: data) {
            entries = decoded
        } else {
            entries = []
        }
    }

    public var all: [ExtensionHeartbeat] {
        lock.lock(); defer { lock.unlock() }
        return entries.sorted { $0.browser < $1.browser }
    }

    public func record(browser: String, version: String) {
        lock.lock()
        if let idx = entries.firstIndex(where: { $0.browser == browser }) {
            entries[idx].lastSeen = Date()
            entries[idx].version = version
        } else {
            entries.append(ExtensionHeartbeat(browser: browser, version: version))
        }
        let snapshot = entries
        lock.unlock()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(snapshot) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }
}
