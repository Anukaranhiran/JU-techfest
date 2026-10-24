import Foundation

// MARK: - Host / domain utilities

public enum DomainUtils {

    /// Multi-label public suffixes we care about for "what is the registrable domain".
    /// This is intentionally a compact allowlist rather than a full Public Suffix List;
    /// unknown suffixes fall back to last-two-labels, which is the conservative choice
    /// for a trust heuristic (it can only *under*-group, never invent trust).
    private static let multiPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.br", "net.br", "org.br", "gov.br",
        "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
        "com.sg", "com.hk", "com.tw", "com.cn", "com.my", "com.ph", "com.vn",
        "com.tr", "com.sa", "com.eg", "com.pk", "com.bd", "com.ng", "com.gh",
        "co.za", "co.ke", "co.il", "co.kr", "or.kr", "co.id", "co.th",
        "com.pl", "com.ua", "com.ru", "com.es", "com.pt", "com.gr", "com.ro",
        "gov.us", "k12.us", "state.us",
    ]

    /// Lowercased host with trailing dot removed and IPv6 brackets stripped.
    public static func normalizeHost(_ raw: String) -> String {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        if host.hasPrefix("[") && host.hasSuffix("]") {
            host.removeFirst()
            host.removeLast()
        }
        return host
    }

    public static func isIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        for part in parts {
            guard let n = Int(part), n >= 0, n <= 255, String(n) == part || part == "0" else { return false }
        }
        return true
    }

    public static func isIPv6(_ host: String) -> Bool {
        host.contains(":") && host.allSatisfy { $0.isHexDigit || $0 == ":" || $0 == "." }
    }

    public static func isIPAddress(_ host: String) -> Bool { isIPv4(host) || isIPv6(host) }

    public enum NetworkScope: Sendable {
        case localhost
        case privateNetwork
        case linkLocal
        case publicInternet
        case unknown
    }

    /// Scope of an IP literal (or a hostname we treat as local).
    public static func scope(ofHost host: String) -> NetworkScope {
        let h = normalizeHost(host)
        if h == "localhost" || h.hasSuffix(".localhost") || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
            return .localhost
        }
        if h.hasSuffix(".local") || h.hasSuffix(".internal") || h.hasSuffix(".home.arpa") {
            return .privateNetwork
        }
        if isIPv4(h) {
            let octets = h.split(separator: ".").compactMap { Int($0) }
            guard octets.count == 4 else { return .unknown }
            if octets[0] == 10 { return .privateNetwork }
            if octets[0] == 172 && (16...31).contains(octets[1]) { return .privateNetwork }
            if octets[0] == 192 && octets[1] == 168 { return .privateNetwork }
            if octets[0] == 169 && octets[1] == 254 { return .linkLocal }
            if octets[0] == 127 { return .localhost }
            return .publicInternet
        }
        if isIPv6(h) {
            let lower = h.lowercased()
            if lower == "::1" { return .localhost }
            if lower.hasPrefix("fe80") { return .linkLocal }
            if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return .privateNetwork }
            return .publicInternet
        }
        return .unknown
    }

    /// eTLD+1 when we can determine it, otherwise the full host.
    public static func registrableDomain(_ host: String) -> String {
        let h = normalizeHost(host)
        guard !h.isEmpty, !isIPAddress(h) else { return h }
        let labels = h.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return h }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        if multiPartSuffixes.contains(lastTwo), labels.count >= 3 {
            return labels.suffix(3).joined(separator: ".")
        }
        // Punycode TLDs and unknown two-part suffixes: keep last two labels.
        return lastTwo
    }

    public static func subdomainLabels(of host: String) -> [String] {
        let h = normalizeHost(host)
        let registrable = registrableDomain(h)
        guard h != registrable, h.hasSuffix("." + registrable) else { return [] }
        let prefix = String(h.dropLast(registrable.count + 1))
        return prefix.split(separator: ".").map(String.init)
    }

    public static func isSubdomain(of host: String, parent: String) -> Bool {
        let h = normalizeHost(host)
        let p = normalizeHost(parent)
        return h == p || h.hasSuffix("." + p)
    }
}

// MARK: - Punycode (RFC 3492) decoder

public enum Punycode {
    private struct DecodeError: Error {}

    /// Decodes one punycode label ("xn--bcher-kva" -> "bücher"). Returns nil on malformed input.
    public static func decodeLabel(_ label: String) -> String? {
        let lower = label.lowercased()
        guard lower.hasPrefix("xn--") else { return nil }
        let payload = String(lower.dropFirst(4))
        guard !payload.isEmpty else { return nil }
        do {
            return try decodePayload(payload)
        } catch {
            return nil
        }
    }

    /// Decodes every punycode label of a host. Returns the unicode host.
    public static func decodeHost(_ host: String) -> String? {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var changed = false
        var out: [String] = []
        for label in labels {
            if let decoded = decodeLabel(label) {
                out.append(decoded)
                changed = true
            } else {
                out.append(label)
            }
        }
        return changed ? out.joined(separator: ".") : nil
    }

    private static func decodePayload(_ input: String) throws -> String {
        let base: UInt32 = 36
        let tMin: UInt32 = 1
        let tMax: UInt32 = 26
        let skew: UInt32 = 38
        let damp: UInt32 = 700
        let initialBias: UInt32 = 72
        let initialN: UInt32 = 128

        func adapt(_ delta: UInt32, _ numPoints: UInt32, _ firstTime: Bool) -> UInt32 {
            var delta = firstTime ? delta / damp : delta / 2
            delta += delta / numPoints
            var k: UInt32 = 0
            while delta > ((base - tMin) * tMax) / 2 {
                delta /= base - tMin
                k += base
            }
            return k + (((base - tMin + 1) * delta) / (delta + skew))
        }

        func digitValue(_ c: Character) throws -> UInt32 {
            guard let ascii = c.asciiValue else { throw DecodeError() }
            switch ascii {
            case Character("0").asciiValue!...Character("9").asciiValue!: return UInt32(ascii - 22)
            case Character("a").asciiValue!...Character("z").asciiValue!: return UInt32(ascii - 97)
            case Character("A").asciiValue!...Character("Z").asciiValue!: return UInt32(ascii - 65)
            default: throw DecodeError()
            }
        }

        var output: [UInt32] = []
        var idx = input.startIndex
        if let delimiter = input.lastIndex(of: "-") {
            for c in input[input.startIndex..<delimiter] {
                guard let ascii = c.asciiValue, ascii < 128 else { return String(input) }
                output.append(UInt32(ascii))
            }
            idx = input.index(after: delimiter)
        }

        var n = initialN
        var i: UInt32 = 0
        var bias = initialBias
        var remaining = input[idx...].map { $0 }

        while !remaining.isEmpty {
            let oldi = i
            var w: UInt32 = 1
            var k = base
            while true {
                guard !remaining.isEmpty else { throw DecodeError() }
                let c = remaining.removeFirst()
                let digit = try digitValue(c)
                i = i &+ digit &* w
                let t: UInt32 = k <= bias ? tMin : (k >= bias &+ tMax ? tMax : k &- bias)
                if digit < t { break }
                w = w &* (base &- t)
                k = k &+ base
            }
            let count = UInt32(output.count) &+ 1
            bias = adapt(i &- oldi, count, oldi == 0)
            n = n &+ i / count
            i = i % count
            guard let scalar = Unicode.Scalar(n) else { throw DecodeError() }
            output.insert(n, at: Int(i))
            _ = scalar
            i = i &+ 1
        }

        var scalars = String.UnicodeScalarView()
        for value in output {
            guard let scalar = Unicode.Scalar(value) else { throw DecodeError() }
            scalars.append(scalar)
        }
        return String(scalars)
    }
}

// MARK: - Unicode script / confusable analysis

public enum ScriptAnalysis {
    public enum ScriptGroup: String, Sendable, CaseIterable {
        case latin, cyrillic, greek, arabic, hebrew, devanagari, han, kana, hangul, thai, armenian, georgian, other
    }

    public static func group(for scalar: Unicode.Scalar) -> ScriptGroup {
        switch scalar.value {
        case 0x0041...0x024F, 0x1E00...0x1EFF: return .latin
        case 0x0370...0x03FF, 0x1F00...0x1FFF: return .greek
        case 0x0400...0x052F, 0x2DE0...0x2DFF, 0xA640...0xA69F: return .cyrillic
        case 0x0590...0x05FF: return .hebrew
        case 0x0600...0x06FF, 0x0750...0x077F: return .arabic
        case 0x0900...0x097F: return .devanagari
        case 0x3040...0x30FF: return .kana
        case 0x4E00...0x9FFF: return .han
        case 0xAC00...0xD7AF: return .hangul
        case 0x0E00...0x0E7F: return .thai
        case 0x0530...0x058F: return .armenian
        case 0x10A0...0x10FF: return .georgian
        default: return .other
        }
    }

    /// Script groups present in a string, ignoring digits/punctuation.
    public static func scripts(in text: String) -> Set<ScriptGroup> {
        var found: Set<ScriptGroup> = []
        for scalar in text.unicodeScalars {
            if CharacterSet.decimalDigits.contains(scalar) { continue }
            if CharacterSet.punctuationCharacters.contains(scalar) { continue }
            if CharacterSet.whitespacesAndNewlines.contains(scalar) { continue }
            // ASCII letters count as Latin so that "аpple" (one Cyrillic letter) is
            // recognised as a mixed-script host instead of a pure Cyrillic one.
            if scalar.value < 128 {
                if CharacterSet.letters.contains(scalar) { found.insert(.latin) }
                continue
            }
            found.insert(group(for: scalar))
        }
        return found
    }

    /// Non-ASCII characters that render almost identically to ASCII letters.
    public static let confusables: [Character: Character] = [
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ѕ": "s", "ԁ": "d", "ј": "j", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
        "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "χ": "x",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
        "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
        "ı": "i", "ɡ": "g", "ⅼ": "l", "ⅰ": "i", "ℝ": "R",
    ]

    /// ASCII-folded transliteration, used to unmask homograph brands.
    public static func asciiFold(_ text: String) -> String {
        var out = ""
        for ch in text {
            if let mapped = confusables[ch] {
                out.append(mapped)
            } else if ch.isASCII {
                out.append(ch)
            } else if let decomposed = String(ch).applyingTransform(.toLatin, reverse: false) {
                out.append(contentsOf: decomposed)
            } else {
                out.append(ch)
            }
        }
        return out
    }

    /// True when a hostname mixes scripts in a way that is virtually never legitimate.
    public static func looksMixedScript(_ host: String) -> (mixed: Bool, scripts: Set<ScriptGroup>) {
        let scripts = scripts(in: host)
        let meaningful = scripts.subtracting([.other])
        if meaningful.count >= 2 { return (true, meaningful) }
        if meaningful.contains(.cyrillic) || meaningful.contains(.greek) {
            // A single non-Latin script is fine for a real IDN, but not when the label
            // is trying to look Latin. The brand-matching layer decides that.
            return (false, meaningful)
        }
        return (false, meaningful)
    }
}

// MARK: - Levenshtein

public enum TextDistance {
    public static func levenshtein(_ a: String, _ b: String) -> Int {
        let aChars = Array(a)
        let bChars = Array(b)
        if aChars.isEmpty { return bChars.count }
        if bChars.isEmpty { return aChars.count }
        var prev = Array(0...bChars.count)
        var cur = [Int](repeating: 0, count: bChars.count + 1)
        for i in 1...aChars.count {
            cur[0] = i
            for j in 1...bChars.count {
                let cost = aChars[i - 1] == bChars[j - 1] ? 0 : 1
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            swap(&prev, &cur)
        }
        return prev[bChars.count]
    }

    /// Collapses common visual substitutions before comparison.
    ///
    /// `one` controls how the digit 1 is folded: "l" catches `paypa1` →
    /// `paypal`; "i" catches `m1crosoft` → `microsoft`. Callers that compare brand
    /// names should check both keys. The letter i is deliberately *not* mapped to
    /// l — doing that turned every `i` into an `l` and hid Microsoft look-alikes.
    public static func homoglyphKey(_ s: String, one: Character = "l") -> String {
        var out = ""
        for ch in s.lowercased() {
            switch ch {
            case "0": out.append("o")
            case "1": out.append(one)
            case "l", "|": out.append("l")
            case "3": out.append("e")
            case "4": out.append("a")
            case "5": out.append("s")
            case "7": out.append("t")
            case "$": out.append("s")
            case "@": out.append("a")
            default: out.append(ch)
            }
        }
        return out.replacingOccurrences(of: "vv", with: "w")
    }

    /// Both useful folds for the digit 1. Used for brand comparison only.
    public static func homoglyphKeys(_ s: String) -> [String] {
        let l = homoglyphKey(s, one: "l")
        let i = homoglyphKey(s, one: "i")
        return l == i ? [l] : [l, i]
    }
}
