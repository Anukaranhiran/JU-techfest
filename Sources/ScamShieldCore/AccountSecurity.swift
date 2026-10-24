import CryptoKit
import Foundation

// MARK: - Password strength (local only)
//
// The password never leaves this process. This is a transparent heuristic, not a
// claim to reproduce a commercial password-strength model.

public struct PasswordStrengthReport: Sendable {
    public struct Finding: Sendable, Identifiable, Hashable {
        public var text: String
        public var good: Bool
        public var id: String { text }
    }
    public var length: Int
    public var score: Int          // 0...4
    public var label: String
    public var estimatedBits: Double
    public var findings: [Finding]
    public var suggestions: [String]
}

public enum PasswordStrength {

    static let commonPasswords: Set<String> = [
        "password", "123456", "123456789", "qwerty", "111111", "12345678", "abc123",
        "password1", "1234567", "12345", "123123", "letmein", "welcome", "admin",
        "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "charlie",
        "aa123456", "donald", "password123", "qwerty123", "1q2w3e4r", "zxc123",
    ]

    public static func evaluate(_ password: String) -> PasswordStrengthReport {
        let chars = Array(password)
        let length = chars.count
        let lower = password.lowercased()
        var findings: [PasswordStrengthReport.Finding] = []
        var suggestions: [String] = []

        let hasLower = chars.contains { $0.isLowercase }
        let hasUpper = chars.contains { $0.isUppercase }
        let hasDigit = chars.contains { $0.isNumber }
        let hasSymbol = chars.contains { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }
        let classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter { $0 }.count

        // Rough entropy from the character pool actually used, with penalties.
        var pool = 0.0
        if hasLower { pool += 26 }
        if hasUpper { pool += 26 }
        if hasDigit { pool += 10 }
        if hasSymbol { pool += 33 }
        var bits = length > 0 && pool > 0 ? Double(length) * log2(pool) : 0

        if commonPasswords.contains(lower) {
            bits = min(bits, 12)
            findings.append(.init(text: "This is one of the most common passwords.", good: false))
            suggestions.append("Choose a password that is not on any common-password list.")
        }
        if length < 12 {
            findings.append(.init(text: "Length is \(length); 12+ characters is recommended.", good: false))
            suggestions.append("Make it longer — length matters more than clever substitutions.")
        } else {
            findings.append(.init(text: "Length is \(length) characters.", good: true))
        }
        if classes < 3 {
            findings.append(.init(text: "Uses \(classes) character class(es).", good: false))
            suggestions.append("Mix upper/lowercase, digits and symbols where the site allows.")
        } else {
            findings.append(.init(text: "Uses \(classes) character classes.", good: true))
        }
        if lower.contains("password") || lower.contains("qwerty") || lower.contains("letmein") {
            findings.append(.init(text: "Contains a predictable word.", good: false))
        }
        if isSequential(lower) || isRepeated(lower) {
            bits *= 0.35
            findings.append(.init(text: "Contains a sequence or repeated pattern.", good: false))
            suggestions.append("Avoid keyboard runs (qwerty) and repeated characters (aaaa).")
        }
        if let year = lower.range(of: #"(19|20)\d{2}"#, options: .regularExpression) {
            _ = year
            bits *= 0.7
            findings.append(.init(text: "Contains a year, which is easy to guess.", good: false))
        }
        if length >= 16 && classes >= 3 && !commonPasswords.contains(lower) {
            findings.append(.init(text: "Long and varied.", good: true))
        }

        let score: Int
        switch bits {
        case ..<28: score = 0
        case ..<40: score = 1
        case ..<60: score = 2
        case ..<80: score = 3
        default: score = 4
        }
        let label = ["Very weak", "Weak", "Reasonable", "Strong", "Very strong"][score]
        if suggestions.isEmpty {
            suggestions.append("Store it in a password manager and use a unique password for every account.")
        }
        suggestions.append("Turn on two-factor authentication; a strong password alone does not stop phishing.")
        return PasswordStrengthReport(length: length, score: score, label: label,
                                      estimatedBits: (bits * 10).rounded() / 10,
                                      findings: findings, suggestions: suggestions)
    }

    static func isSequential(_ value: String) -> Bool {
        let scalars = Array(value.unicodeScalars.map { Int($0.value) })
        guard scalars.count >= 4 else { return false }
        var ascending = 0, descending = 0
        for index in 1..<scalars.count {
            let delta = scalars[index] - scalars[index - 1]
            if delta == 1 { ascending += 1 }
            if delta == -1 { descending += 1 }
        }
        return ascending >= 3 || descending >= 3
    }

    static func isRepeated(_ value: String) -> Bool {
        guard value.count >= 4 else { return false }
        var run = 1
        let chars = Array(value)
        for index in 1..<chars.count {
            if chars[index] == chars[index - 1] { run += 1; if run >= 4 { return true } } else { run = 1 }
        }
        return false
    }
}

// MARK: - Have I Been Pwned

public struct BreachRecord: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var title: String
    public var domain: String
    public var breachDate: String?
    public var pwnCount: Int?
    public var dataClasses: [String]
    public var isVerified: Bool
    public var id: String { name }
}

public struct BreachReport: Sendable {
    public var email: String
    public var breaches: [BreachRecord]
    public var status: ReputationStatus
    public var detail: String
    public var checks: [CheckRecord]
    public var limitations: [String]
}

public enum HaveIBeenPwned {

    public static func breaches(email: String, apiKey: String) async -> BreachReport {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.contains("@"), trimmed.count >= 5 else {
            return BreachReport(email: trimmed, breaches: [], status: .error,
                                detail: "Enter a valid email address.",
                                checks: [CheckRecord(name: "Email validation", state: .failed, detail: "Not an email address.")],
                                limitations: [])
        }
        guard !apiKey.trimmingCharacters(in: .whitespaces).isEmpty else {
            return BreachReport(email: trimmed, breaches: [], status: .notConfigured,
                                detail: "No Have I Been Pwned API key is configured.",
                                checks: [CheckRecord(name: "HIBP breach lookup", state: .skipped,
                                                     detail: "Requires a paid HIBP API key. This is not a clean result.")],
                                limitations: ["Without a key, ScamShield cannot check breach data. Do not read this as “not breached”."])
        }
        guard let encoded = trimmed.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            return BreachReport(email: trimmed, breaches: [], status: .error, detail: "Could not encode the address.",
                                checks: [], limitations: [])
        }
        let endpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false"
        do {
            let response = try await SafeFetcher.fetch(endpoint, timeout: 12, maxBytes: 512 * 1024, extraHeaders: [
                "hibp-api-key": apiKey,
                "User-Agent": "ScamShield-macOS",
            ])
            switch response.status {
            case 200:
                guard let root = try? JSONSerialization.jsonObject(with: response.body) as? [[String: Any]] else {
                    return BreachReport(email: trimmed, breaches: [], status: .error, detail: "HIBP returned an unexpected body.",
                                        checks: [CheckRecord(name: "HIBP breach lookup", state: .failed, detail: "Malformed response.")],
                                        limitations: [])
                }
                let records = root.compactMap { item -> BreachRecord? in
                    guard let name = item["Name"] as? String else { return nil }
                    return BreachRecord(name: name,
                                        title: item["Title"] as? String ?? name,
                                        domain: item["Domain"] as? String ?? "",
                                        breachDate: item["BreachDate"] as? String,
                                        pwnCount: item["PwnCount"] as? Int,
                                        dataClasses: item["DataClasses"] as? [String] ?? [],
                                        isVerified: item["IsVerified"] as? Bool ?? false)
                }
                return BreachReport(email: trimmed, breaches: records, status: records.isEmpty ? .clean : .malicious,
                                    detail: records.isEmpty ? "HIBP returned no breaches for this address."
                                        : "This address appears in \(records.count) breach(es).",
                                    checks: [CheckRecord(name: "HIBP breach lookup", state: .passed, detail: "HTTP 200, \(records.count) breach record(s).")],
                                    limitations: ["HIBP only knows about breaches it has catalogued. Absence is not proof of safety.",
                                                  "The email address was sent to haveibeenpwned.com with your API key."])
            case 404:
                return BreachReport(email: trimmed, breaches: [], status: .clean,
                                    detail: "HIBP has no breach record for this address.",
                                    checks: [CheckRecord(name: "HIBP breach lookup", state: .passed, detail: "HTTP 404: no record.")],
                                    limitations: ["No record is not a guarantee; breaches are added over time."])
            case 401:
                return BreachReport(email: trimmed, breaches: [], status: .error, detail: "HIBP rejected the API key.",
                                    checks: [CheckRecord(name: "HIBP breach lookup", state: .failed, detail: "HTTP 401.")], limitations: [])
            case 429:
                return BreachReport(email: trimmed, breaches: [], status: .error, detail: "HIBP rate limit reached.",
                                    checks: [CheckRecord(name: "HIBP breach lookup", state: .failed, detail: "HTTP 429.")], limitations: [])
            default:
                return BreachReport(email: trimmed, breaches: [], status: .error, detail: "HIBP returned HTTP \(response.status).",
                                    checks: [CheckRecord(name: "HIBP breach lookup", state: .failed, detail: "HTTP \(response.status).")], limitations: [])
            }
        } catch {
            return BreachReport(email: trimmed, breaches: [], status: .error,
                                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription,
                                checks: [CheckRecord(name: "HIBP breach lookup", state: .failed, detail: error.localizedDescription)],
                                limitations: ["The lookup failed. This is not a clean result."])
        }
    }

    /// Privacy-preserving password check (k-anonymity). Only the first five hex
    /// characters of the SHA-1 hash leave the machine.
    public static func passwordBreachCount(_ password: String) async -> (count: Int?, detail: String) {
        guard !password.isEmpty else { return (nil, "Enter a password to check.") }
        let digest = Insecure.SHA1.hash(data: Data(password.utf8))
        let hex = digest.map { String(format: "%02X", $0) }.joined()
        let prefix = String(hex.prefix(5))
        let suffix = String(hex.dropFirst(5))
        do {
            let response = try await SafeFetcher.fetch("https://api.pwnedpasswords.com/range/\(prefix)",
                                                       timeout: 10, maxBytes: 2 * 1024 * 1024,
                                                       extraHeaders: ["Add-Padding": "true"])
            guard response.status == 200 else {
                return (nil, "The password range service returned HTTP \(response.status). This is not a clean result.")
            }
            for line in response.bodyText.components(separatedBy: .newlines) {
                let parts = line.split(separator: ":")
                guard parts.count == 2 else { continue }
                if parts[0].uppercased() == suffix {
                    return (Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0,
                            "This password appears in known breach corpora.")
                }
            }
            return (0, "This password was not found in the Pwned Passwords range. Absence is not proof of safety.")
        } catch {
            return (nil, "Password breach lookup failed: \((error as? LocalizedError)?.errorDescription ?? error.localizedDescription). This is not a clean result.")
        }
    }
}
