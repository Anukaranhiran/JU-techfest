import Foundation

// MARK: - Scam Intelligence graph
//
// Everything here is derived from scans this app performed on this Mac. There is no
// downloaded feed and no invented relationship: an edge exists only because the same
// scan produced both signals.

public final class IntelGraph: Codable, Sendable {

    public enum NodeKind: String, Codable, Sendable {
        case domain
        case indicator
        case scan
    }

    public struct Node: Codable, Sendable, Identifiable, Hashable {
        public var id: String
        public var kind: NodeKind
        public var label: String
        public var detail: String
        public var occurrences: Int
        public var highestLevel: RiskLevel?
        public var lastSeen: Date?
    }

    public struct Edge: Codable, Sendable, Hashable {
        public var source: String
        public var target: String
        /// Always "co-occurred-in-scan" or "contains" — never an unobserved link.
        public var relation: String
        public var occurrences: Int
    }

    public struct Cluster: Codable, Sendable, Identifiable, Hashable {
        public var id: String
        public var domains: [String]
        public var sharedIndicators: [String]
        public var highestLevel: RiskLevel
        public var explanation: String
    }

    public var nodes: [Node]
    public var edges: [Edge]
    public var clusters: [Cluster]
    public var generatedAt: Date
    public var scansConsidered: Int
    public var disclaimer: String = "Relationships below come only from scans performed on this Mac. Nothing here is a threat-intelligence feed, and co-occurrence is not proof of shared ownership."

    public enum CodingKeys: String, CodingKey {
        case nodes, edges, clusters, generatedAt, scansConsidered, disclaimer
    }

    public init(nodes: [Node], edges: [Edge], clusters: [Cluster], generatedAt: Date, scansConsidered: Int) {
        self.nodes = nodes
        self.edges = edges
        self.clusters = clusters
        self.generatedAt = generatedAt
        self.scansConsidered = scansConsidered
    }

    public var domainNodes: [Node] {
        nodes.filter { $0.kind == .domain }.sorted { lhs, rhs in
            if lhs.occurrences != rhs.occurrences { return lhs.occurrences > rhs.occurrences }
            return lhs.label < rhs.label
        }
    }

    public var indicatorNodes: [Node] {
        nodes.filter { $0.kind == .indicator }.sorted { $0.occurrences > $1.occurrences }
    }

    public func edges(from id: String) -> [Edge] {
        edges.filter { $0.source == id || $0.target == id }
    }
}

public enum IntelBuilder {

    /// Evidence categories that describe *how* a URL is built rather than a one-off
    /// phrase, so they are worth using as shared indicators.
    static let indicatorCategories: Set<Evidence.Category> = [.brand, .structure, .redirect, .scheme, .domain]

    public static func build(from entries: [HistoryEntry], maxDomains: Int = 80) -> IntelGraph {
        struct DomainAggregate {
            var count = 0
            var level: RiskLevel?
            var last: Date
            var indicators: [String: Int] = [:]
            var titles: [String: String] = [:]
        }

        var domains: [String: DomainAggregate] = [:]
        var considered = 0

        for entry in entries {
            guard entry.scan.kind != .message || entry.scan.host != nil else { continue }
            guard let domain = entry.scan.registrableDomain ?? entry.scan.host, !domain.isEmpty else { continue }
            considered += 1
            var agg = domains[domain] ?? DomainAggregate(count: 0, level: nil, last: entry.scan.createdAt)
            agg.count += 1
            if let level = entry.scan.riskLevel {
                if agg.level == nil || level > (agg.level ?? .low) { agg.level = level }
            }
            if entry.scan.createdAt > agg.last { agg.last = entry.scan.createdAt }
            for item in entry.scan.evidence where indicatorCategories.contains(item.category) && item.weight > 0 {
                agg.indicators[item.code, default: 0] += 1
                agg.titles[item.code] = item.title
            }
            domains[domain] = agg
        }

        // Keep the most relevant domains so the graph stays readable.
        let ranked = domains.sorted { lhs, rhs in
            let l = lhs.value.level?.rank ?? -1
            let r = rhs.value.level?.rank ?? -1
            if l != r { return l > r }
            if lhs.value.count != rhs.value.count { return lhs.value.count > rhs.value.count }
            return lhs.key < rhs.key
        }.prefix(maxDomains)

        var nodes: [IntelGraph.Node] = []
        var edges: [IntelGraph.Edge] = []
        var indicatorTotals: [String: Int] = [:]
        var indicatorTitles: [String: String] = [:]
        var indicatorDomains: [String: Set<String>] = [:]

        for (domain, agg) in ranked {
            nodes.append(IntelGraph.Node(
                id: "domain:" + domain,
                kind: .domain,
                label: domain,
                detail: "\(agg.count) local scan\(agg.count == 1 ? "" : "s") · highest \(agg.level?.title ?? "unverified")",
                occurrences: agg.count,
                highestLevel: agg.level,
                lastSeen: agg.last
            ))
            for (code, count) in agg.indicators {
                indicatorTotals[code, default: 0] += count
                indicatorTitles[code] = agg.titles[code]
                indicatorDomains[code, default: []].insert(domain)
                edges.append(IntelGraph.Edge(source: "domain:" + domain, target: "indicator:" + code,
                                             relation: "co-occurred-in-scan", occurrences: count))
            }
        }

        for (code, total) in indicatorTotals.sorted(by: { $0.value > $1.value }).prefix(25) {
            nodes.append(IntelGraph.Node(
                id: "indicator:" + code,
                kind: .indicator,
                label: indicatorTitles[code] ?? code,
                detail: "Observed in \(indicatorDomains[code]?.count ?? 0) domain(s), \(total) time(s)",
                occurrences: total,
                highestLevel: nil,
                lastSeen: nil
            ))
        }

        // Clusters: domains that share at least two observed indicators.
        var clusters: [IntelGraph.Cluster] = []
        let domainKeys = ranked.map(\.key)
        var visited: Set<String> = []
        for domain in domainKeys where !visited.contains(domain) {
            guard let agg = domains[domain] else { continue }
            var group: Set<String> = [domain]
            var shared: Set<String> = []
            for other in domainKeys where other != domain {
                guard let otherAgg = domains[other] else { continue }
                let common = Set(agg.indicators.keys).intersection(otherAgg.indicators.keys)
                if common.count >= 2 {
                    group.insert(other)
                    shared.formUnion(common)
                }
            }
            guard group.count >= 2 else { continue }
            let level = group.compactMap { domains[$0]?.level }.max() ?? .low
            let names = shared.sorted()
            clusters.append(IntelGraph.Cluster(
                id: "cluster:" + (names.first ?? domain),
                domains: group.sorted(),
                sharedIndicators: names.map { indicatorTitles[$0] ?? $0 },
                highestLevel: level,
                explanation: "These domains each produced the same \(names.count) structural indicator(s) in separate local scans. That is a pattern worth noting, not proof of a single operator."
            ))
            visited.formUnion(group)
        }

        return IntelGraph(nodes: nodes,
                          edges: edges,
                          clusters: clusters.sorted { $0.domains.count > $1.domains.count },
                          generatedAt: Date(),
                          scansConsidered: considered)
    }
}
