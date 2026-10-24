import Foundation

// MARK: - Ephemeral relay / dynamic-DNS awareness
//
// Tunnelling services such as LocalXpose, ngrok and Cloudflare Quick Tunnels issue a
// random hostname on a shared parent domain. The URL itself therefore tells us one
// important thing: the real content lives on a *temporary, user-controlled* endpoint
// that cannot be verified from the domain alone. That is not proof of malice (people
// use these for demos every day), but it is also not a reason to show a safe verdict.
//
// This is deliberately *not* a blocklist: the parent service is never blocked, and the
// evidence weight alone cannot produce a "malicious" verdict. It exists so that a
// random `*.loclx.io` link is reported as unverified relay infrastructure instead of
// being scored 0 and labelled LOW RISK.

public struct RelayMatch: Sendable, Hashable {
    public enum Kind: String, Sendable {
        case ephemeralTunnel
        case dynamicDNS
        case wildcardDNS
        case sharedHosting
    }

    public let kind: Kind
    public let provider: String
    /// The parent domain that owns the endpoint.
    public let parent: String
    /// True when the scanned host is a child of the provider (the actual relay endpoint).
    public let isEndpoint: Bool
    public let detail: String
}

public enum RelayInfrastructure {

    private static let tunnels: [String: String] = [
        "loclx.io": "LocalXpose",
        "ngrok.io": "ngrok",
        "ngrok-free.app": "ngrok",
        "ngrok.app": "ngrok",
        "ngrok.dev": "ngrok",
        "trycloudflare.com": "Cloudflare Quick Tunnel",
        "loca.lt": "localtunnel",
        "localtunnel.me": "localtunnel",
        "serveo.net": "Serveo",
        "pinggy.io": "Pinggy",
        "pinggy.link": "Pinggy",
        "tunnelto.dev": "Tunnelto",
        "tunnelto.live": "Tunnelto",
        "bore.pub": "bore",
        "bore.direct": "bore",
        "localhost.run": "localhost.run",
        "devtunnels.ms": "Microsoft Dev Tunnels",
        "tunl.me": "Tunl",
        "tunnelmole.com": "Tunnelmole",
        "zrok.io": "zrok",
        "cloudpub.me": "CloudPub",
        "telebit.io": "Telebit",
        "pagekite.me": "PageKite",
        "exp.direct": "Exp",
        "lhr.life": "localhost.run",
        "jprq.live": "jprq",
    ]

    private static let dynamicDNS: [String: String] = [
        "duckdns.org": "DuckDNS",
        "no-ip.org": "No-IP",
        "noip.me": "No-IP",
        "ddns.net": "No-IP",
        "hopto.org": "No-IP",
        "zapto.org": "No-IP",
        "sytes.net": "No-IP",
        "myftp.org": "No-IP",
        "serveftp.com": "No-IP",
        "3utilities.com": "No-IP",
        "dynu.net": "Dynu",
        "freeddns.org": "FreeDNS",
        "afraid.org": "FreeDNS",
        "mooo.com": "FreeDNS",
        "dynalias.net": "Dynalias",
        "mywire.org": "MyWire",
    ]

    private static let wildcardDNS: [String: String] = [
        "sslip.io": "sslip.io",
        "nip.io": "nip.io",
        "xip.io": "xip.io",
    ]

    // Free static-app hosting. These are legitimate platforms, so the weight is low and
    // only acts as context when other evidence is already present.
    private static let sharedHosting: [String: String] = [
        "workers.dev": "Cloudflare Workers",
        "pages.dev": "Cloudflare Pages",
        "vercel.app": "Vercel",
        "netlify.app": "Netlify",
        "web.app": "Firebase Hosting",
        "firebaseapp.com": "Firebase Hosting",
        "glitch.me": "Glitch",
        "repl.co": "Replit",
        "gitpod.io": "Gitpod",
        "onrender.com": "Render",
        "fly.dev": "Fly.io",
    ]

    /// Matches the host against known relay infrastructure. Returns nil for ordinary hosts.
    public static func match(host: String) -> RelayMatch? {
        let h = DomainUtils.normalizeHost(host)
        guard !h.isEmpty else { return nil }
        let registrable = DomainUtils.registrableDomain(h)

        if let provider = tunnels[registrable] ?? tunnels[h] {
            let endpoint = h != registrable
            return RelayMatch(
                kind: .ephemeralTunnel,
                provider: provider,
                parent: registrable,
                isEndpoint: endpoint,
                detail: endpoint
                    ? "This is a temporary relay endpoint on \(provider) (\(registrable)). Tunnel hostnames are issued to anyone in seconds, are reused, and the content behind them can change without the URL changing. A structure-only check cannot establish what is served here."
                    : "This is the \(provider) relay service's own domain. The service is legitimate; only endpoints beneath it are user-controlled."
            )
        }

        if let provider = dynamicDNS[registrable] ?? dynamicDNS[h] {
            let endpoint = h != registrable
            return RelayMatch(
                kind: .dynamicDNS,
                provider: provider,
                parent: registrable,
                isEndpoint: endpoint,
                detail: endpoint
                    ? "This hostname belongs to the free dynamic-DNS provider \(provider) (\(registrable)). The name is user-chosen and can be repointed at any time, so the URL is not evidence of who operates the destination."
                    : "This is the \(provider) dynamic-DNS service's own domain."
            )
        }

        if let provider = wildcardDNS[registrable] ?? wildcardDNS[h] {
            let endpoint = h != registrable
            return RelayMatch(
                kind: .wildcardDNS,
                provider: provider,
                parent: registrable,
                isEndpoint: endpoint,
                detail: endpoint
                    ? "The hostname embeds an IP address through \(provider) wildcard DNS. The visible name can hide the real destination address."
                    : "This is the \(provider) wildcard-DNS service's own domain."
            )
        }

        if let provider = sharedHosting[registrable] ?? sharedHosting[h] {
            let endpoint = h != registrable
            if endpoint {
                return RelayMatch(
                    kind: .sharedHosting,
                    provider: provider,
                    parent: registrable,
                    isEndpoint: true,
                    detail: "The site is hosted on \(provider) shared infrastructure. That is common and legitimate, but it means the parent domain says nothing about this particular tenant."
                )
            }
        }

        return nil
    }

    /// True when a subdomain looks machine-generated (mixed letters and digits, no
    /// dictionary shape). This is only used alongside relay infrastructure, never alone.
    static func looksGenerated(_ label: String) -> Bool {
        guard (8...40).contains(label.count) else { return false }
        let letters = label.filter(\.isLetter).count
        let digits = label.filter(\.isNumber).count
        guard letters >= 4, digits >= 2 else { return false }
        return true
    }

    public static func evidence(for host: String) -> [Evidence] {
        guard let match = match(host: host), match.isEndpoint else { return [] }
        var out: [Evidence] = []
        switch match.kind {
        case .ephemeralTunnel:
            out.append(Evidence(code: "host.ephemeral-tunnel",
                title: "Temporary relay endpoint (\(match.provider))",
                detail: match.detail + " Treat the destination as unverified until the page itself is inspected or a reputation provider returns a result.",
                weight: 22, category: .domain))
        case .dynamicDNS:
            out.append(Evidence(code: "host.dynamic-dns",
                title: "Dynamic-DNS hostname (\(match.provider))",
                detail: match.detail,
                weight: 20, category: .domain))
        case .wildcardDNS:
            out.append(Evidence(code: "host.wildcard-dns",
                title: "IP-embedding wildcard DNS (\(match.provider))",
                detail: match.detail,
                weight: 18, category: .domain))
        case .sharedHosting:
            out.append(Evidence(code: "host.shared-hosting",
                title: "Shared application hosting",
                detail: match.detail,
                weight: 5, category: .context))
        }

        // A generated-looking tenant name on relay infrastructure is worth one extra
        // weak signal; on its own it is much too common to mean anything.
        if match.kind == .ephemeralTunnel {
            let labels = DomainUtils.subdomainLabels(of: host)
            if labels.contains(where: looksGenerated) {
                out.append(Evidence(code: "host.generated-subdomain",
                    title: "Machine-generated relay hostname",
                    detail: "The left-most label looks randomly generated, which is how tunnel services allocate throw-away endpoints.",
                    weight: 6, category: .structure))
            }
        }
        return out
    }
}

// MARK: - Host classification for SSRF protection

public extension DomainUtils {
    /// True when the address is outside the public internet and must never be fetched
    /// by ScamShield on an attacker's behalf.
    static func isBlockedDestination(_ host: String) -> Bool {
        let h = normalizeHost(host)
        if h == "localhost" || h.hasSuffix(".localhost") || h.hasSuffix(".local")
            || h.hasSuffix(".internal") || h.hasSuffix(".home.arpa") { return true }

        if isIPv4(h) {
            let parts = h.split(separator: ".").compactMap { Int($0) }
            guard parts.count == 4 else { return true }
            let a = parts[0], b = parts[1]
            if a == 0 || a == 10 || a == 127 { return true }
            if a == 100 && (64...127).contains(b) { return true }     // CGNAT
            if a == 169 && b == 254 { return true }                    // link-local + cloud metadata
            if a == 172 && (16...31).contains(b) { return true }
            if a == 192 && b == 168 { return true }
            if a == 192 && b == 0 && parts[2] == 0 { return true }
            if a == 198 && (18...19).contains(b) { return true }       // benchmarking
            if a == 198 && b == 51 && parts[2] == 100 { return true }  // TEST-NET-2
            if a == 203 && b == 0 && parts[2] == 113 { return true }   // TEST-NET-3
            if a >= 224 { return true }                                // multicast/reserved/broadcast
            return false
        }

        if isIPv6(h) {
            let lower = h.lowercased()
            if lower == "::" || lower == "::1" { return true }
            if lower.hasPrefix("::ffff:") { return true }              // IPv4-mapped
            if lower.hasPrefix("fe80") || lower.hasPrefix("fc") || lower.hasPrefix("fd") { return true }
            if lower.hasPrefix("ff") { return true }                   // multicast
            if lower.hasPrefix("2001:db8") { return true }             // documentation
            return false
        }
        return false
    }
}
