import XCTest
@testable import ScamShieldCore

final class DomainAgeRegressionTests: XCTestCase {
    func testVerifiedSubHourAgeIsStrongButNotPhishingProof() {
        let registration = DomainRegistration(registrar: "Fixture Registry", createdAt: Date(timeIntervalSinceNow: -1800),
            expiresAt: nil, updatedAt: nil, statuses: [], ageDays: 0)
        let report = DomainInspector.assess(registration: registration, host: "fresh.example",
                                            registrableDomain: "fresh.example", now: Date())
        XCTAssertFalse(report.failed)
        XCTAssertEqual(report.evidence.first?.code, "domain.registered-under-1-hour")
        XCTAssertEqual(report.evidence.first?.weight, 50)
        let result = ScanEngine().applyingDomainAgeReport(ScanEngine().scanURL("https://fresh.example/"), report: report)
        XCTAssertEqual(result.riskLevel, .high)
        XCTAssertTrue(result.evidence.first?.title.contains("Highly suspicious") == true)
    }

    func testUnavailableAgeIsHonestAndDoesNotLookClean() {
        let report = DomainAgeReport(host: "unknown.example", registrableDomain: "unknown.example",
            registration: nil, ageSeconds: nil, evidence: [],
            check: .init(name: "Domain registration age", state: .unavailable, detail: "RDAP unavailable"),
            limitations: ["Domain age is unknown, not a clearance."], failed: true)
        let result = ScanEngine().applyingDomainAgeReport(ScanEngine().scanURL("https://unknown.example/"), report: report)
        XCTAssertEqual(result.riskLevel, .inconclusive)
        XCTAssertTrue(result.limitations.contains { $0.contains("unknown") })
        XCTAssertFalse(result.evidence.contains { $0.code.contains("domain.registered") })
    }

    func testOlderAgeDoesNotCreateSuspicionByItself() {
        let registration = DomainRegistration(registrar: "Fixture Registry", createdAt: Date(timeIntervalSinceNow: -86400 * 365),
            expiresAt: nil, updatedAt: nil, statuses: [], ageDays: 365)
        let report = DomainInspector.assess(registration: registration, host: "old.example",
                                            registrableDomain: "old.example", now: Date())
        XCTAssertEqual(report.evidence.first?.code, "domain.age")
        XCTAssertEqual(report.evidence.first?.weight, -4)
    }
}
