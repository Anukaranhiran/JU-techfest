import Foundation

// MARK: - Evaluation

public struct FixtureOutcome: Codable, Sendable, Identifiable, Hashable {
    public var fixtureID: String
    public var expectation: String
    public var actualVerdict: String
    public var score: Int
    public var detected: Bool
    public var evidenceTitles: [String]
    public var durationMs: Double

    public var id: String { fixtureID }
}

public struct EvaluationFailure: Codable, Sendable, Hashable {
    public var fixtureID: String
    public var expected: String
    public var actual: String
    public var detail: String
}

public struct EvaluationRun: Codable, Sendable {
    public var startedAt: Date
    public var durationMs: Double
    public var outcomes: [FixtureOutcome]
    public var truePositives: Int
    public var trueNegatives: Int
    public var falsePositives: Int
    public var falseNegatives: Int
    public var failures: [EvaluationFailure]
    public var understated: [EvaluationFailure]
    public var fixturesAreSynthetic: Bool = true
    public var caveat: String = "Fixtures are hand-written synthetic cases plus real public benign URLs. They measure the deterministic engine's behaviour on known shapes, not real-world detection rates."

    public var total: Int { outcomes.count }
    public var precision: Double {
        let denom = truePositives + falsePositives
        return denom == 0 ? 0 : Double(truePositives) / Double(denom)
    }
    public var recall: Double {
        let denom = truePositives + falseNegatives
        return denom == 0 ? 0 : Double(truePositives) / Double(denom)
    }
    public var f1: Double {
        precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall)
    }
    public var accuracy: Double {
        total == 0 ? 0 : Double(truePositives + trueNegatives) / Double(total)
    }
}

public struct EvaluationRunner {
    private let engine: ScanEngine

    public init(engine: ScanEngine = ScanEngine()) {
        self.engine = engine
    }

    public func scan(_ fixture: ScanFixture) -> ScanResult {
        switch fixture.kind {
        case .url: return engine.scanURL(fixture.payload)
        case .message: return engine.scanMessage(fixture.payload)
        case .email: return engine.scanEmail(fixture.payload)
        }
    }

    public func run(_ fixtures: [ScanFixture]) -> EvaluationRun {
        let started = Date()
        var outcomes: [FixtureOutcome] = []
        var tp = 0, tn = 0, fp = 0, fn = 0
        var failures: [EvaluationFailure] = []
        var understated: [EvaluationFailure] = []

        for fixture in fixtures {
            let result = scan(fixture)
            let level = result.riskLevel
            let detected = (level ?? .low) >= .medium

            switch fixture.expectation {
            case .benign:
                if detected {
                    fp += 1
                    failures.append(EvaluationFailure(fixtureID: fixture.id, expected: "low",
                                                      actual: result.displayVerdict,
                                                      detail: "False positive: \(result.topEvidence.first?.title ?? "unknown signal")"))
                } else {
                    tn += 1
                }
            case .suspicious:
                if detected { tp += 1 } else {
                    fn += 1
                    failures.append(EvaluationFailure(fixtureID: fixture.id, expected: "medium+",
                                                      actual: result.displayVerdict,
                                                      detail: result.limitations.first ?? "no signal reached threshold"))
                }
            case .hostile:
                if detected { tp += 1 } else {
                    fn += 1
                    failures.append(EvaluationFailure(fixtureID: fixture.id, expected: "high+",
                                                      actual: result.displayVerdict, detail: "not detected"))
                }
                if let level, level < .high {
                    understated.append(EvaluationFailure(fixtureID: fixture.id, expected: "high+",
                                                         actual: result.displayVerdict,
                                                         detail: "detected but understated"))
                }
            }

            outcomes.append(FixtureOutcome(
                fixtureID: fixture.id,
                expectation: fixture.expectation.rawValue,
                actualVerdict: result.displayVerdict,
                score: result.riskScore,
                detected: detected,
                evidenceTitles: result.topEvidence.prefix(3).map(\.title),
                durationMs: result.durationMs
            ))
        }

        return EvaluationRun(startedAt: started,
                             durationMs: Date().timeIntervalSince(started) * 1000,
                             outcomes: outcomes,
                             truePositives: tp,
                             trueNegatives: tn,
                             falsePositives: fp,
                             falseNegatives: fn,
                             failures: failures,
                             understated: understated)
    }

    public func runBuiltIn() -> EvaluationRun { run(FixtureLibrary.fixtures) }
}
