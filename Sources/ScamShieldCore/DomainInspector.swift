import Foundation

// MARK: - Domain inspector (DNS over HTTPS + RDAP)

public struct DNSAnswer: Codable, Sendable, Hashable, Identifiable {
    public var type: String
    public var value: String
    public var ttl: Int?
    public var id: String { type + "|" + value }
}

public struct DomainRegistration: Codable, Sendable, Hashable {
    public var registrar: String?
    public var createdAt: Date?
    public var expiresAt: Date?
    public var updatedAt: Date?
    public var statuses: [String]
    public var ageDays: Int?
}

public struct DomainReport: Sendable {
    public var host: String
    public var registrableDomain: String
    public var answers: [DNSAnswer]
    public var registration: DomainRegistration?
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var sources: [String]
    public var failed: Bool

    public var addresses: [String] { answers.filter { $0.type == "A" || $0.type == "AAAA" }.map(\.value) }
    public var mx: [String] { answers.filter { $0.type == "MX" }.map(\.value) }
    public var nameservers: [String] { answers.filter { $0.type == "NS" }.map(\.value) }
}

/// The domain-age portion of a live URL scan. Kept separate from DNS/reputation so
/// every checker can merge exactly the same registration evidence.
public struct DomainAgeReport: Sendable {
    public var host: String
    public var registrableDomain: String
    public var registration: DomainRegistration?
    /// Whole seconds since the RDAP registration event, only when a trustworthy
    /// creation timestamp was published.
    public var ageSeconds: Int?
    public var evidence: [Evidence]
    public var check: CheckRecord
    public var limitations: [String]
    public var failed: Bool
}

public enum DomainInspector {

    public static func inspect(_ input: String) async -> DomainReport {
        let normalized = DomainUtils.normalizeHost(
            input.replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "http://", with: "")
                .split(separator: "/").first.map(String.init) ?? input)
        let registrable = DomainUtils.registrableDomain(normalized)
        var checks: [CheckRecord] = []
        var limitations: [String] = []
        var sources: [String] = []
        var evidence: [Evidence] = []

        guard !normalized.isEmpty, !DomainUtils.isIPAddress(normalized) else {
            return DomainReport(host: normalized, registrableDomain: registrable, answers: [], registration: nil,
                                evidence: [], checks: [CheckRecord(name: "Host validation", state: .failed,
                                                                  detail: "Enter a domain name, not an IP address.")],
                                limitations: ["An IP address has no registration record. Use the IP checker instead."],
                                sources: [], failed: true)
        }

        var answers: [DNSAnswer] = []
        var dnsFailures = 0
        for type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] {
            do {
                let records = try await dnsQuery(name: registrable, type: type)
                answers.append(contentsOf: records)
                checks.append(CheckRecord(name: "DNS \(type)", state: .passed,
                                          detail: records.isEmpty ? "No \(type) records returned." : "\(records.count) record(s)."))
            } catch {
                dnsFailures += 1
                checks.append(CheckRecord(name: "DNS \(type)", state: .failed,
                                          detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
            }
        }
        sources.append("Cloudflare DNS-over-HTTPS")

        var registration: DomainRegistration?
        do {
            registration = try await rdap(domain: registrable)
            checks.append(CheckRecord(name: "RDAP registration", state: .passed,
                                      detail: registration?.createdAt.map { "Registered \(FmtDate.string.string(from: $0))." } ?? "No creation event published."))
            sources.append("RDAP")
        } catch {
            checks.append(CheckRecord(name: "RDAP registration", state: .failed,
                                      detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
            limitations.append("Registration data was unavailable from RDAP. Domain age is unknown, which is not a clearance.")
        }

        if let registration {
            let age = assess(registration: registration, host: normalized,
                             registrableDomain: registrable, now: Date())
            evidence.append(contentsOf: age.evidence)
            checks.append(age.check)
        }
        if answers.contains(where: { $0.type == "A" || $0.type == "AAAA" }) == false && dnsFailures == 0 {
            evidence.append(Evidence(code: "domain.no-address", title: "No address records",
                detail: "The domain has no A or AAAA record, so it does not currently serve a website.",
                weight: 4, category: .domain))
        }
        if dnsFailures > 0 {
            limitations.append("\(dnsFailures) DNS query type(s) failed. Missing data is not evidence of safety.")
        }
        limitations.append("DNS answers can be geo-specific and can change between queries. This is a snapshot, not a reputation verdict.")
        limitations.append("Queries were sent to Cloudflare DNS-over-HTTPS; RDAP queries go to rdap.org. The domain name is shared with those services.")

        return DomainReport(host: normalized, registrableDomain: registrable, answers: answers,
                            registration: registration, evidence: evidence, checks: checks,
                            limitations: limitations, sources: sources, failed: dnsFailures == 6)
    }

    /// Runs RDAP only for the registrable domain and returns the shared age evidence.
    /// This is what live URL scans call; no DNS-over-HTTPS work is duplicated.
    public static func checkAge(_ input: String, now: Date = Date()) async -> DomainAgeReport {
        let normalized = DomainUtils.normalizeHost(
            input.replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "http://", with: "")
                .split(separator: "/").first.map(String.init) ?? input)
        let registrable = DomainUtils.registrableDomain(normalized)
        guard !normalized.isEmpty, !DomainUtils.isIPAddress(normalized) else {
            return DomainAgeReport(
                host: normalized, registrableDomain: registrable, registration: nil, ageSeconds: nil,
                evidence: [], check: CheckRecord(name: "Domain registration age", state: .unavailable,
                    detail: "An IP literal has no domain registration record, so domain age cannot be checked."),
                limitations: ["Domain age is unavailable for an IP address. That is unknown, not safe."],
                failed: true)
        }
        do {
            let registration = try await rdap(domain: registrable)
            return assess(registration: registration, host: normalized,
                          registrableDomain: registrable, now: now)
        } catch {
            let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return DomainAgeReport(
                host: normalized, registrableDomain: registrable, registration: nil, ageSeconds: nil,
                evidence: [], check: CheckRecord(name: "Domain registration age", state: .unavailable,
                    detail: "Registration data was unavailable: \(detail)"),
                limitations: ["Domain age could not be verified from RDAP. It is unknown, not a clearance."],
                failed: true)
        }
    }

    /// Shared deterministic age rules. The exact creation timestamp is required for
    /// the under-one-hour finding; a registry that publishes only a date cannot
    /// confirm that precision, so it is reported as unavailable instead of guessed.
    static func assess(registration: DomainRegistration, host: String,
                       registrableDomain: String, now: Date = Date()) -> DomainAgeReport {
        guard let created = registration.createdAt else {
            return DomainAgeReport(
                host: host, registrableDomain: registrableDomain, registration: registration, ageSeconds: nil,
                evidence: [], check: CheckRecord(name: "Domain registration age", state: .unavailable,
                    detail: "RDAP published no creation event for \(registrableDomain), so age is unknown."),
                limitations: ["RDAP had a record for \(registrableDomain) but no creation timestamp. Age is unknown, not a clearance."],
                failed: true)
        }

        let seconds = max(0, Int(now.timeIntervalSince(created)))
        let minutes = seconds / 60
        let days = seconds / 86400
        let timestamp = ISO8601DateFormatter().string(from: created)
        var evidence: [Evidence] = []
        var detail = "Registered \(timestamp)."

        if seconds < 3600 {
            detail += " That is \(max(1, minutes)) minute(s) ago."
            evidence.append(Evidence(
                code: "domain.registered-under-1-hour",
                title: "Highly suspicious: domain registered less than 1 hour ago",
                detail: "RDAP confirms \(registrableDomain) was registered \(max(1, minutes)) minute(s) ago. Domains this new have no history and are disproportionately used for short-lived phishing. Age alone does not prove phishing, but it is a strong independent risk signal.",
                // HIGHLY SUSPICIOUS is a warning band, not confirmation of phishing.
                // The evidence explicitly states that age alone is not proof.
                weight: 50, category: .domain))
        } else if days <= 30 {
            detail += " That is \(days) day(s) ago."
            evidence.append(Evidence(
                code: "domain.newly-registered", title: "Domain registered \(days) day(s) ago",
                detail: "Newly registered domains are disproportionately used for phishing because they have no history to lose.",
                weight: 24, category: .domain))
        } else if days <= 90 {
            detail += " That is \(days) days ago."
            evidence.append(Evidence(
                code: "domain.recent", title: "Domain registered \(days) days ago",
                detail: "The domain is recent. That is not proof of abuse, but it is worth weighing with other signals.",
                weight: 12, category: .domain))
        } else {
            detail += " That is \(days) days ago."
            evidence.append(Evidence(
                code: "domain.age", title: "Domain age \(days) days",
                detail: "The registration is older than 90 days. Age alone does not establish trust; domains are bought and repurposed.",
                weight: -4, category: .domain))
        }
        return DomainAgeReport(
            host: host, registrableDomain: registrableDomain, registration: registration,
            ageSeconds: seconds, evidence: evidence,
            check: CheckRecord(name: "Domain registration age", state: .passed, detail: detail),
            limitations: ["Registration age comes from the registry's RDAP creation event. It does not prove who operates the site or whether the domain was transferred."],
            failed: false)
    }

    // MARK: DoH

    static func dnsQuery(name: String, type: String) async throws -> [DNSAnswer] {
        guard let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) else { return [] }
        let endpoint = "https://cloudflare-dns.com/dns-query?name=\(encoded)&type=\(type)"
        let response = try await SafeFetcher.fetch(endpoint, timeout: 8, maxBytes: 128 * 1024,
                                                   extraHeaders: ["accept": "application/dns-json"])
        guard response.status == 200,
              let root = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw SafeNetworkError(kind: .transport, detail: "DNS-over-HTTPS returned HTTP \(response.status).")
        }
        let status = root["Status"] as? Int ?? -1
        guard status == 0 || status == 3 else {
            throw SafeNetworkError(kind: .transport, detail: "DNS resolver returned status \(status).")
        }
        let answer = root["Answer"] as? [[String: Any]] ?? []
        return answer.compactMap { item in
            guard let data = item["data"] as? String else { return nil }
            let typeNumber = item["type"] as? Int ?? 0
            let label: String
            switch typeNumber {
            case 1: label = "A"
            case 2: label = "NS"
            case 5: label = "CNAME"
            case 6: label = "SOA"
            case 15: label = "MX"
            case 16: label = "TXT"
            case 28: label = "AAAA"
            case 257: label = "CAA"
            default: label = type
            }
            return DNSAnswer(type: label, value: data, ttl: item["TTL"] as? Int)
        }
    }

    // MARK: RDAP

    static func rdap(domain: String) async throws -> DomainRegistration {
        let endpoint = "https://rdap.org/domain/\(domain)"
        let response = try await SafeFetcher.fetch(endpoint, timeout: 10, maxBytes: 512 * 1024,
                                                   extraHeaders: ["accept": "application/rdap+json"])
        if response.status == 404 {
            throw SafeNetworkError(kind: .transport, detail: "RDAP has no record for \(domain).")
        }
        guard response.status == 200,
              let root = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw SafeNetworkError(kind: .transport, detail: "RDAP returned HTTP \(response.status).")
        }
        let events = root["events"] as? [[String: Any]] ?? []
        func event(_ action: String) -> Date? {
            guard let item = events.first(where: { ($0["eventAction"] as? String)?.lowercased() == action }),
                  let raw = item["eventDate"] as? String else { return nil }
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            return formatter.date(from: raw) ?? ISO8601DateFormatter().date(from: raw)
        }
        let created = event("registration")
        let expires = event("expiration")
        let updated = event("last changed") ?? event("last update")
        let statuses = root["status"] as? [String] ?? []

        var registrar: String?
        if let entities = root["entities"] as? [[String: Any]] {
            for entity in entities {
                let roles = entity["roles"] as? [String] ?? []
                guard roles.contains("registrar") else { continue }
                if let vcard = entity["vcardArray"] as? [Any], vcard.count > 1,
                   let fields = vcard[1] as? [[Any]] {
                    for field in fields where (field.first as? String) == "fn" {
                        registrar = field.count > 3 ? field[3] as? String : nil
                    }
                }
                if registrar == nil { registrar = entity["handle"] as? String }
            }
        }

        let age: Int? = created.map { max(0, Int(Date().timeIntervalSince($0) / 86400)) }
        return DomainRegistration(registrar: registrar, createdAt: created, expiresAt: expires,
                                  updatedAt: updated, statuses: statuses, ageDays: age)
    }
}

public enum FmtDate {
    public static let string: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter
    }()
}

// MARK: - IP reputation

public struct IPReport: Sendable {
    public var ip: String
    public var scope: DomainUtils.NetworkScope
    public var reverseDNS: String?
    public var providerOutcomes: [ProviderOutcome]
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var failed: Bool
}

public enum IPReputationChecker {
    public static func check(_ input: String, virusTotalKey: String) async -> IPReport {
        let ip = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard DomainUtils.isIPAddress(ip) else {
            return IPReport(ip: ip, scope: .unknown, reverseDNS: nil, providerOutcomes: [],
                            evidence: [], checks: [CheckRecord(name: "IP validation", state: .failed,
                                                               detail: "“\(input)” is not a valid IPv4/IPv6 address.")],
                            limitations: ["Enter a bare IP address."], failed: true)
        }
        var evidence: [Evidence] = []
        var checks: [CheckRecord] = []
        var outcomes: [ProviderOutcome] = []
        let scope = DomainUtils.scope(ofHost: ip)
        let reverse = ReverseDNS.lookup(ip)
        checks.append(CheckRecord(name: "Reverse DNS", state: reverse == nil ? .unavailable : .passed,
                                  detail: reverse ?? "No PTR record returned."))
        switch scope {
        case .localhost:
            evidence.append(Evidence(code: "ip.loopback", title: "Loopback address",
                                     detail: "This address is your own computer.", weight: 0, category: .context))
        case .privateNetwork:
            evidence.append(Evidence(code: "ip.private", title: "Private network address",
                                     detail: "This address is inside a private range and is not reachable from the public internet.",
                                     weight: 0, category: .context))
        case .linkLocal:
            evidence.append(Evidence(code: "ip.link-local", title: "Link-local address",
                                     detail: "Link-local addresses are auto-assigned on the local segment.", weight: 4, category: .context))
        case .publicInternet:
            break
        case .unknown:
            break
        }

        if scope == .publicInternet {
            if !virusTotalKey.trimmingCharacters(in: .whitespaces).isEmpty {
                do {
                    let response = try await SafeFetcher.fetch("https://www.virustotal.com/api/v3/ip_addresses/\(ip)",
                        timeout: 10, maxBytes: 256 * 1024, extraHeaders: ["x-apikey": virusTotalKey])
                    if response.status == 200,
                       let root = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
                       let data = root["data"] as? [String: Any],
                       let attributes = data["attributes"] as? [String: Any],
                       let stats = attributes["last_analysis_stats"] as? [String: Any] {
                        let malicious = stats["malicious"] as? Int ?? 0
                        let suspicious = stats["suspicious"] as? Int ?? 0
                        let total = ["malicious", "suspicious", "harmless", "undetected"].reduce(0) { $0 + (stats[$1] as? Int ?? 0) }
                        if malicious > 0 {
                            outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .malicious,
                                                            detail: "\(malicious) of \(total) engines flagged this IP."))
                            evidence.append(Evidence(code: "ip.reputation-malicious", title: "IP flagged by VirusTotal",
                                                     detail: "\(malicious) of \(total) engines flagged \(ip).", weight: 80, category: .reputation))
                        } else if suspicious > 0 {
                            outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .suspicious,
                                                            detail: "\(suspicious) of \(total) engines marked this IP suspicious."))
                            evidence.append(Evidence(code: "ip.reputation-suspicious", title: "IP marked suspicious",
                                                     detail: "\(suspicious) of \(total) engines marked \(ip) suspicious.", weight: 40, category: .reputation))
                        } else {
                            outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .clean,
                                                            detail: "No engine flagged this IP. Not a guarantee."))
                            evidence.append(Evidence(code: "ip.reputation-clean", title: "No VirusTotal detections",
                                                     detail: "No engine in the stored analysis flagged \(ip).", weight: -6, category: .reputation))
                        }
                        checks.append(CheckRecord(name: "VirusTotal IP reputation", state: .passed, detail: "HTTP 200."))
                    } else {
                        outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .error,
                                                        detail: "VirusTotal returned HTTP \(response.status)."))
                        checks.append(CheckRecord(name: "VirusTotal IP reputation", state: .failed, detail: "HTTP \(response.status)."))
                    }
                } catch {
                    outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .error,
                                                    detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
                    checks.append(CheckRecord(name: "VirusTotal IP reputation", state: .failed, detail: error.localizedDescription))
                }
            } else {
                outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .notConfigured,
                                                detail: "No VirusTotal API key configured. Unknown is not clean."))
                checks.append(CheckRecord(name: "VirusTotal IP reputation", state: .skipped, detail: "No API key."))
            }
        }

        return IPReport(ip: ip, scope: scope, reverseDNS: reverse, providerOutcomes: outcomes,
                        evidence: evidence, checks: checks,
                        limitations: ["Reverse DNS and reputation describe the address at query time; shared hosting IPs can be reassigned.",
                                      "Private and reserved addresses are never sent to external providers."],
                        failed: false)
    }
}

public enum ReverseDNS {
    public static func lookup(_ ip: String) -> String? {
        guard DomainUtils.isIPv4(ip) else { return nil }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: inet_addr(ip))
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let status = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sock in
                getnameinfo(sock, length, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard status == 0 else { return nil }
        return String(cString: host)
    }
}
