import Foundation

// MARK: - URL parsing

/// A parsed web URL. Parsing is done by hand (rather than URLComponents alone) so we
/// keep the exact authority the user saw — userinfo, odd ports, punycode, IDN — because
/// those are the parts attackers exploit.
public struct ParsedURL: Sendable, Hashable {
    public let raw: String
    public let scheme: String
    public let userInfo: String?
    public let host: String
    public let port: Int?
    public let path: String
    public let query: String
    public let fragment: String
    /// Encoding/decoding notes discovered while parsing.
    public let parseNotes: [String]

    public var registrableDomain: String { DomainUtils.registrableDomain(host) }
    public var isWebScheme: Bool { scheme == "http" || scheme == "https" }
    public var isIDN: Bool { host.unicodeScalars.contains { $0.value > 127 } || host.contains("xn--") }
    public var unicodeHost: String? { Punycode.decodeHost(host) }

    public var hostAndPath: String {
        path.isEmpty ? host : host + path
    }

    public var normalized: String {
        var s = "\(scheme)://"
        if let userInfo { s += userInfo + "@" }
        s += host
        if let port { s += ":\(port)" }
        s += path.isEmpty ? "/" : path
        if !query.isEmpty { s += "?" + query }
        if !fragment.isEmpty { s += "#" + fragment }
        return s
    }

    public static let webSchemes: Set<String> = ["http", "https"]
    /// Schemes that can execute code or read local files. Never handed to a browser.
    public static let dangerousSchemes: Set<String> = [
        "javascript", "data", "vbscript", "file", "blob", "about", "chrome", "chrome-extension",
        "jar", "ms-msdt", "search-ms", "shell", "smb", "ftp", "telnet",
    ]

    public static func parse(_ input: String) throws -> ParsedURL {
        var notes: [String] = []
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)

        // Strip invisible characters that are used to defeat naive scanners.
        let invisible = CharacterSet(charactersIn: "\u{200B}\u{200C}\u{200D}\u{FEFF}\u{00AD}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}")
        if text.unicodeScalars.contains(where: { invisible.contains($0) }) {
            notes.append("URL contained invisible/control characters (zero-width or bidi) that were removed before analysis.")
            text = String(String.UnicodeScalarView(text.unicodeScalars.filter { !invisible.contains($0) }))
        }
        guard !text.isEmpty else { throw ScamShieldError.invalidURL("empty") }

        // Scheme
        var scheme = "https"
        var rest = text
        if let colon = text.firstIndex(of: ":") {
            let candidate = String(text[text.startIndex..<colon]).lowercased()
            let validScheme = !candidate.isEmpty && candidate.allSatisfy { $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." }
                && (candidate.first?.isLetter ?? false)
            if validScheme {
                scheme = candidate
                rest = String(text[text.index(after: colon)...])
                if rest.hasPrefix("//") { rest = String(rest.dropFirst(2)) }
            }
        } else if !text.contains("://") {
            notes.append("No scheme supplied; analysed as https.")
        }

        if !ParsedURL.webSchemes.contains(scheme) {
            let authority = rest.split(separator: "/", maxSplits: 1).first.map(String.init) ?? ""
            return ParsedURL(raw: input, scheme: scheme, userInfo: nil, host: authority.lowercased(),
                             port: nil, path: "", query: "", fragment: "", parseNotes: notes)
        }

        // Fragment / query / path
        var authority = rest
        var fragment = ""
        var query = ""
        var path = ""
        if let hash = authority.firstIndex(of: "#") {
            fragment = String(authority[authority.index(after: hash)...])
            authority = String(authority[authority.startIndex..<hash])
        }
        if let q = authority.firstIndex(of: "?") {
            query = String(authority[authority.index(after: q)...])
            authority = String(authority[authority.startIndex..<q])
        }
        if let slash = authority.firstIndex(of: "/") {
            path = String(authority[authority.startIndex..<authority.endIndex]).replacingOccurrences(of: authority[authority.startIndex..<slash], with: "")
            authority = String(authority[authority.startIndex..<slash])
            if !path.hasPrefix("/") { path = "/" + path }
        }
        if let q = path.firstIndex(of: "?") {
            if query.isEmpty { query = String(path[path.index(after: q)...]) }
            path = String(path[path.startIndex..<q])
        }

        // userinfo@host
        var userInfo: String?
        if let at = authority.lastIndex(of: "@") {
            userInfo = String(authority[authority.startIndex..<at])
            authority = String(authority[authority.index(after: at)...])
            notes.append("Authority contains “@” userinfo — everything before “@” is ignored by the browser.")
        }

        // host + port (IPv6 aware)
        var host = authority
        var port: Int?
        if authority.hasPrefix("[") {
            if let close = authority.firstIndex(of: "]") {
                host = String(authority[authority.index(after: authority.startIndex)..<close])
                let after = authority[authority.index(after: close)...]
                if after.hasPrefix(":"), let p = Int(after.dropFirst()) { port = p }
            }
        } else if let colon = authority.lastIndex(of: ":") {
            let portPart = String(authority[authority.index(after: colon)...])
            if !portPart.isEmpty, let p = Int(portPart) {
                port = p
                host = String(authority[authority.startIndex..<colon])
            }
        }

        host = DomainUtils.normalizeHost(host)
        if path.isEmpty { path = "/" }
        guard !host.isEmpty else { throw ScamShieldError.invalidURL(input) }
        let invalidHostCharacters = CharacterSet.whitespacesAndNewlines
            .union(CharacterSet(charactersIn: "<>\"'`{}|\\^~!$&()*+,;="))
        if host.unicodeScalars.contains(where: { invalidHostCharacters.contains($0) }) {
            throw ScamShieldError.invalidURL("host contains invalid characters")
        }
        if host.contains("/") || host.contains("?") || host.contains("#") {
            throw ScamShieldError.invalidURL("host contains path separators")
        }

        return ParsedURL(raw: input, scheme: scheme, userInfo: userInfo, host: host, port: port,
                         path: path, query: query, fragment: fragment, parseNotes: notes)
    }
}

// MARK: - URL heuristics

public enum URLAnalyzer {

    static let shortenerHosts: Set<String> = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
        "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "bit.do", "lnkd.in", "s.id",
        "v.gd", "shorte.st", "adf.ly", "bl.ink", "t.ly", "short.io", "urlz.fr", "clck.ru",
    ]

    /// TLDs that are disproportionately abused. Weighted low: plenty of real businesses
    /// use them, so this alone must never block anything.
    static let elevatedRiskTLDs: Set<String> = [
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "click", "link", "work",
        "support", "zip", "mov", "cam", "rest", "buzz", "monster", "quest", "sbs",
        "cfd", "lol", "loan", "download", "stream", "gdn", "bid", "win", "date",
        "review", "country", "science", "party", "racing", "trade", "accountant",
    ]

    static let dangerousExtensions: Set<String> = [
        "exe", "msi", "apk", "dmg", "pkg", "scr", "vbs", "bat", "cmd", "jar", "ps1",
        "iso", "img", "hta", "lnk", "reg", "zip", "rar", "7z", "ace",
    ]

    static let accountKeywords: Set<String> = [
        "login", "signin", "sign-in", "logon", "verify", "verification", "verified",
        "confirm", "account", "secure", "security", "update", "billing", "payment",
        "invoice", "password", "passwd", "credential", "otp", "2fa", "mfa", "code",
        "unlock", "suspended", "locked", "appeal", "recovery", "recover", "reset",
        "wallet", "seed", "phrase", "airdrop", "claim", "refund", "customs", "parcel",
        "delivery", "tax", "irs", "hmrc", "rebate", "gift", "reward", "bonus", "prize",
        "winner", "giveaway", "validate", "authenticate", "authorize", "sso", "webscr",
        "portal", "notice", "alert", "urgent", "deadline",
    ]

    static let redirectParams: Set<String> = [
        "url", "u", "redirect", "redirect_uri", "redirect_url", "next", "continue",
        "target", "dest", "destination", "return", "returnurl", "return_url", "r",
        "link", "goto", "out", "view", "to", "ref", "forward",
    ]

    static let hostedFileHosts: Set<String> = [
        "drive.google.com", "docs.google.com", "dropbox.com", "1drv.ms", "onedrive.live.com",
        "mega.nz", "mediafire.com", "wetransfer.com", "sharepoint.com", "box.com",
    ]

    public static func analyze(_ url: ParsedURL) -> [Evidence] {
        var evidence: [Evidence] = []

        func add(_ code: String, _ title: String, _ detail: String, _ weight: Int, _ category: Evidence.Category) {
            evidence.append(Evidence(code: code, title: title, detail: detail, weight: weight, category: category))
        }

        for note in url.parseNotes {
            add("url.parse-note", "Unusual URL encoding", note, 12, .structure)
        }

        // --- Scheme -------------------------------------------------------------
        if !url.isWebScheme {
            if ParsedURL.dangerousSchemes.contains(url.scheme) {
                add("scheme.dangerous", "Dangerous URL scheme",
                    "“\(url.scheme):” can execute code or read local files. It is not a web page and ScamShield will not hand it to a browser.",
                    60, .scheme)
            } else {
                add("scheme.non-web", "Non-web scheme",
                    "“\(url.scheme):” is not a web link, so it cannot be opened in a browser and its destination is unknown.",
                    30, .scheme)
            }
        } else if url.scheme == "http" {
            add("transport.no-tls", "No transport encryption",
                "This link uses http://, so the page and anything typed into it travel unencrypted and can be modified in transit.",
                6, .transport)
        }

        // --- Host shape ---------------------------------------------------------
        let scope = DomainUtils.scope(ofHost: url.host)
        switch scope {
        case .localhost:
            add("context.localhost", "Local machine address",
                "This is a loopback address (your own computer). It is not reachable by an attacker from the internet, so it is treated as local development rather than a remote threat.",
                -20, .context)
        case .privateNetwork:
            add("context.private-network", "Private network address",
                "This address is on a private/LAN range. Traffic stays inside your network, so external reputation checks do not apply. Only trust it if you recognise the device.",
                -8, .context)
        case .linkLocal:
            add("context.link-local", "Link-local address",
                "Link-local addresses are auto-assigned on the local segment and can indicate a device pretending to be a router or printer. Verify the device before entering credentials.",
                6, .context)
        case .publicInternet, .unknown:
            break
        }

        // Relay / dynamic-DNS infrastructure. This is a host-shape signal, not a
        // reputation result: it says the destination is temporary and unverifiable,
        // which is exactly why it must prevent a "nothing found = safe" verdict.
        evidence.append(contentsOf: RelayInfrastructure.evidence(for: url.host))

        if DomainUtils.isIPAddress(url.host), scope == .publicInternet {
            add("host.ip-literal", "Raw IP address instead of a domain",
                "Legitimate services publish a domain name. Bare IP addresses skip certificate name checks and are common in phishing and malware delivery.",
                14, .domain)
        }

        if let port = url.port, ![80, 443].contains(port), ![80, 443].contains(port) {
            if scope == .localhost || scope == .privateNetwork {
                add("host.unusual-port-local", "Non-standard local port",
                    "Port \(port) on a local/private host is normal for development servers.",
                    -2, .context)
            } else {
                add("host.unusual-port", "Unusual network port",
                    "The link uses port \(port) rather than 443. Services on odd ports are frequently attacker-controlled panels.",
                    10, .domain)
            }
        }

        if let userInfo = url.userInfo, !userInfo.isEmpty {
            add("url.userinfo", "Misleading “@” section",
                "The part before “@” (“\(userInfo.prefix(40))”) is user information, not the site. Browsers ignore it, so the real destination is \(url.host).",
                18, .structure)
        }

        let subLabels = DomainUtils.subdomainLabels(of: url.host)
        if subLabels.count >= 5 {
            add("host.excessive-subdomains", "Unusually deep subdomain chain",
                "\(subLabels.count) subdomain labels before “\(url.registrableDomain)” hide the real destination at the end of the hostname.",
                10, .structure)
        } else if subLabels.count >= 3 {
            add("host.many-subdomains", "Several subdomain labels",
                "The host uses \(subLabels.count) subdomain labels; long chains are often used to bury the real domain.",
                5, .structure)
        }

        if url.host.contains("xn--") {
            let decoded = Punycode.decodeHost(url.host) ?? "?"
            add("host.punycode", "Punycode (internationalised) domain",
                "The host is punycode-encoded and displays as “\(decoded)”. Punycode is legitimate for real IDNs but is also the standard vehicle for look-alike domains.",
                18, .domain)
        }

        let mixed = ScriptAnalysis.looksMixedScript(url.unicodeHost ?? url.host)
        if mixed.mixed {
            let names = mixed.scripts.map(\.rawValue).sorted().joined(separator: " + ")
            add("host.mixed-script", "Mixed-script homograph domain",
                "The hostname mixes \(names) characters, which render as look-alike Latin letters. This is almost never legitimate.",
                32, .domain)
        }

        if subLabels.joined().contains(where: { $0.unicodeScalars.contains { $0.value > 127 } }) {
            add("host.unicode-subdomain", "Non-ASCII characters in subdomain",
                "A subdomain contains non-Latin characters, a common way to fake a familiar name.",
                12, .domain)
        }

        let digitsInDomain = url.registrableDomain.filter(\.isNumber).count
        if digitsInDomain >= 4 {
            add("host.digits", "Digit-heavy domain",
                "The domain contains \(digitsInDomain) digits, typical of auto-generated phishing infrastructure.",
                6, .domain)
        }

        let hyphens = url.registrableDomain.filter { $0 == "-" }.count
        if hyphens >= 3 {
            add("host.hyphens", "Hyphen-heavy domain",
                "The registrable domain has \(hyphens) hyphens, often used to stitch a brand onto a descriptive phrase.",
                7, .domain)
        }

        if let tld = url.host.split(separator: ".").last.map(String.init)?.lowercased(),
           elevatedRiskTLDs.contains(tld) {
            add("host.tld", "Higher-abuse top-level domain",
                "“.\(tld)” has a high share of abuse relative to its size. This is a weak signal on its own and is never used alone to block.",
                8, .domain)
        }

        if shortenerHosts.contains(url.registrableDomain) || shortenerHosts.contains(url.host) {
            add("host.shortener", "Link shortener hides the destination",
                "The real destination is chosen when the short link is clicked, so the URL text cannot be verified ahead of time. ScamShield will not call a shortener safe.",
                20, .redirect)
        }

        // --- Path / query -------------------------------------------------------
        let pathExt = (url.path as NSString).pathExtension.lowercased()
        if dangerousExtensions.contains(pathExt) {
            add("path.dangerous-file", "Downloads an executable/archive",
                "The link points at a “.\(pathExt)” file. Executables and archives are the main delivery vehicle for malware.",
                22, .content)
        }

        let hostKeywords = BrandImpersonation.tokenize(url.host).intersection(accountKeywords)
        if !hostKeywords.isEmpty {
            add("path.keyword-in-host", "Account-pressure words in the domain",
                "The hostname itself contains “\(hostKeywords.sorted().joined(separator: ", "))”, which legitimate brands rarely need in a domain.",
                14, .content)
        }

        let pathTokens = BrandImpersonation.tokenize(url.path + " " + url.query)
        let pathKeywords = pathTokens.intersection(accountKeywords)
        if pathKeywords.count >= 2 {
            add("path.keywords", "Multiple credential-theft keywords in path",
                "Path/query contains “\(pathKeywords.sorted().prefix(4).joined(separator: ", "))”. Phishing kits reuse these names.",
                10, .content)
        } else if pathKeywords.count == 1, !hostKeywords.isEmpty {
            add("path.keyword", "Credential keyword in path",
                "The path contains “\(pathKeywords.first ?? "")”.",
                4, .content)
        }

        // Embedded destination in the query string (open redirect / double link).
        for (name, value) in queryPairs(url.query) {
            let lowerName = name.lowercased()
            if redirectParams.contains(lowerName), looksLikeURL(value) {
                add("redirect.param", "Open-redirect parameter",
                    "The parameter “\(name)” carries another absolute URL (“\(value.prefix(60))”). The visible link therefore is not the destination.",
                    14, .redirect)
                break
            }
        }
        if containsEmbeddedURL(url.query) && !evidence.contains(where: { $0.code == "redirect.param" }) {
            add("redirect.embedded", "Another URL inside the query",
                "The query string embeds a second URL, so the final destination is decided after the click.",
                10, .redirect)
        }

        let encodedCount = url.path.filter { $0 == "%" }.count + url.query.filter { $0 == "%" }.count
        if encodedCount >= 6 {
            add("path.encoding", "Heavily percent-encoded",
                "The path/query contains \(encodedCount) escape sequences, which can obfuscate the real destination from human readers.",
                6, .structure)
        }
        if url.path.lowercased().contains("%25") || url.query.lowercased().contains("%25") {
            add("path.double-encoding", "Double-encoded characters",
                "A “%25” sequence means the link is encoded twice — a common filter-evasion trick.",
                10, .structure)
        }

        if url.normalized.count > 180 {
            add("url.length", "Very long URL",
                "The URL is \(url.normalized.count) characters; long URLs are used to push the real domain out of view.",
                6, .structure)
        } else if url.normalized.count > 110 {
            add("url.long", "Long URL",
                "The URL is \(url.normalized.count) characters, which can hide the true host in a preview.",
                3, .structure)
        }

        if url.host.contains("..") || url.host.hasPrefix(".") {
            add("host.malformed", "Malformed hostname",
                "The hostname contains empty labels, which no legitimate service publishes.",
                12, .domain)
        }

        // --- Brand impersonation ------------------------------------------------
        let brandSignals = BrandImpersonation.signals(for: url)
        for signal in brandSignals.prefix(3) {
            let weight: Int
            switch signal.kind {
            case .homoglyph: weight = 30
            case .typoDistance: weight = 26
            case .exactTokenWrongDomain: weight = 24
            case .subdomainOnly: weight = 20
            case .punycode: weight = 22
            case .comboSuffix: weight = 16
            }
            add("brand.\(signal.kind.rawValue)", "Impersonates \(signal.brand)", signal.detail, weight, .brand)
        }

        // Brand name in the path of an unrelated host (e.g. http://203.0.113.45/paypal/login).
        if BrandRegistry.officialBrand(forHost: url.host) == nil {
            let pathBrands = pathTokens.compactMap { token in BrandRegistry.brands.first { $0.tokens.contains(token) } }
            if let brand = pathBrands.first, let official = brand.domains.first {
                add("brand.path-token", "\(brand.name) name in the path, not the domain",
                    "The path mentions “\(brand.name)” but the host is \(url.registrableDomain), not \(official). Brand names in paths are how look-alike hosts borrow trust.",
                    14, .brand)
                if DomainUtils.isIPAddress(url.host), scope == .publicInternet {
                    add("brand.ip-path-combo", "Brand login on a bare IP address",
                        "A \(brand.name) login path is served from a raw IP address. Legitimate brands publish named domains with valid certificates, so this combination is a strong credential-harvest indicator.",
                        10, .brand)
                }
            }
        }

        // A strong brand look-alike combined with a credential-path keyword. The
        // individual signals are already counted; this specifically captures the
        // phishing URL pattern (paypa1.com/login, amaz0n-.../signin) without making
        // an ordinary brand mention enough to reach HIGH.
        let strongBrandKind = brandSignals.contains {
            [.homoglyph, .typoDistance, .subdomainOnly].contains($0.kind)
        }
        if strongBrandKind, !pathKeywords.isEmpty,
           BrandRegistry.officialBrand(forHost: url.host) == nil {
            add("brand.lookalike-credential-combo", "Brand look-alike with a credential path",
                "The host is a look-alike for a known brand and the URL path contains “\(pathKeywords.sorted().prefix(3).joined(separator: ", "))”. A lookalike domain plus an account path is the standard URL shape of a fake login.",
                8, .brand)
        }

        // --- Machine-generated / padded structure --------------------------------
        // Adapted from PhishLens (MIT). Low-weight context that complements, rather
        // than replaces, the brand, typo and relay checks above.
        evidence.append(contentsOf: DeceptiveStructure.analyze(url))

        // --- Protective evidence ------------------------------------------------
        if let official = BrandRegistry.officialBrand(forHost: url.host) {
            add("domain.official", "Official \(official.name) domain",
                "“\(url.registrableDomain)” is \(official.name)'s own domain. Structure heuristics still apply, but brand impersonation is ruled out.",
                -30, .domain)
        }

        if scope == .publicInternet || scope == .unknown {
            if hostedFileHosts.contains(url.registrableDomain) || hostedFileHosts.contains(url.host) {
                add("context.file-host", "Hosted file service",
                    "The link is on a mainstream file-hosting service. Shared documents there are a common lure, so the shared item itself still matters.",
                    -4, .context)
            }
        }

        if url.host == url.registrableDomain, subLabels.isEmpty, scope == .unknown, !url.host.contains(".") {
            add("host.single-label", "Single-label hostname",
                "“\(url.host)” has no dot, so it resolves only on your local network (intranet or a hosts-file entry).",
                0, .context)
        }

        return evidence
    }

    // MARK: helpers

    static func queryPairs(_ query: String) -> [(String, String)] {
        guard !query.isEmpty else { return [] }
        return query.split(separator: "&").map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(parts.first ?? "")
            let value = parts.count > 1 ? String(parts[1]).removingPercentEncoding ?? String(parts[1]) : ""
            return (name, value)
        }
    }

    static func looksLikeURL(_ value: String) -> Bool {
        let lower = value.lowercased()
        return lower.hasPrefix("http://") || lower.hasPrefix("https://") || lower.hasPrefix("//")
    }

    static func containsEmbeddedURL(_ query: String) -> Bool {
        let lower = query.lowercased()
        return lower.contains("http%3a") || lower.contains("https%3a") || lower.contains("://")
    }
}
