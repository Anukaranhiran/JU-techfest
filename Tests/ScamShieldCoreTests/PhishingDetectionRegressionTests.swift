import XCTest
@testable import ScamShieldCore

final class PhishingDetectionRegressionTests: XCTestCase {
    private let engine = ScanEngine()
    // Reconstructed from demonstrated parser failures, NOT a capture of the reported
    // phishing page: the live endpoint currently serves only "404 TUNNEL NOT FOUND".
    private let harvestingHTML = """
    <html><head><title>PayPal sign in</title></head><body>
    <h1>PayPal account verification</h1>
    <p>Your account will be suspended. Verify immediately.</p>
    <form action=https://collector.example/session method=post>
      <input name=email type = 'email'>
      <input name=secret type = "password">
      <button>Verify account</button>
    </form></body></html>
    """

    private func inspect(_ html: String, url: String = "https://portal.example/", status: Int = 200,
                         type: String = "text/html", truncated: Bool = false) -> PageInspection {
        PageInspector.analyze(response: SafeHTTPResponse(requestedURL: url, finalURL: url, status: status,
            headers: ["content-type": type], body: Data(html.utf8), redirects: [], truncated: truncated, elapsedMs: 1), requestedURL: url)
    }

    func testValidHTMLAttributeVariantsPreservePhishingEvidence() {
        for url in ["https://portal.example/", "https://preview.loclx.io/"] {
            let page = inspect(harvestingHTML, url: url)
            XCTAssertTrue(page.hasPasswordForm)
            XCTAssertEqual(page.forms.first?.actionHost, "collector.example")
            XCTAssertTrue(page.hasCredentialExternalForm)
            let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
            XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high)
            XCTAssertTrue(result.evidence.contains { $0.code == "page.brand-credential-combo" })
            XCTAssertTrue(result.evidence.contains { $0.code == "page.credential-pressure-combo" })
            XCTAssertNil(result.aiAnalysis)
            print("FIXTURE branded credential harvesting \(url): \(result.displayVerdict) \(result.riskScore)/100; AI not used")
        }
    }

    func testWhitespacePasswordMarkupWithoutOtherRiskStillEscalates() {
        let html = "<title>PayPal sign in</title><form action=/session><input type = 'password'></form>"
        let page = inspect(html)
        let result = engine.applyingPageInspection(engine.scanURL("https://portal.example/"), inspection: page)
        XCTAssertTrue(page.hasPasswordForm)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high, "\(result.riskScore) \(result.topEvidence)")
        print("FIXTURE whitespace password field: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testMissingReputationNeverErasesPageHighFloor() {
        let page = inspect("<form action='https://collector.example/'><input type='password'></form>", url: "https://example.com/")
        let base = engine.scanURL("https://example.com/")
        XCTAssertEqual(base.riskScore, 0)
        let high = engine.applyingPageInspection(base, inspection: page)
        XCTAssertEqual(high.riskLevel, .high)
        XCTAssertEqual(high.riskScore, 50, "The merger must retain this combination floor, not just recompute the 40-point sum")
        for state: ReputationStatus in [.notConfigured, .unknown, .error, .clean] {
            let result = engine.applyingReputation(high, outcome: .init(status: state, detail: "Controlled no-match/unavailable fixture"))
            XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high, "\(state)")
            XCTAssertGreaterThanOrEqual(result.riskScore, high.riskScore, "\(state)")
            let reputationFirst = engine.applyingReputation(base, outcome: .init(status: state, detail: "Controlled fixture"))
            XCTAssertGreaterThanOrEqual(engine.applyingPageInspection(reputationFirst, inspection: page).riskLevel ?? .low, .high)
            print("FIXTURE page HIGH then reputation \(state.rawValue): \(result.displayVerdict) \(result.riskScore)/100")
        }
    }

    func testLegitimateLoginInstructionsAndUnrelatedFormsDoNotForceHigh() {
        let html = """
        <title>Sign in</title><p>Enter your password. Verify your account.</p>
        <form action=/session><input type = 'password'></form>
        <form action='https://search.example/'><input name=q></form>
        """
        for url in ["https://www.paypal.com/signin", "https://accounts.example/", "https://preview.loclx.io/"] {
            let page = inspect(html, url: url)
            XCTAssertTrue(page.hasPasswordForm)
            XCTAssertFalse(page.hasCredentialExternalForm)
            let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
            XCTAssertLessThan(result.riskLevel ?? .critical, .high, "\(url): \(result.riskScore) \(result.topEvidence)")
            XCTAssertFalse(page.evidence.contains { $0.code == "page.credential-pressure-combo" })
            print("FIXTURE legitimate login + unrelated search \(url): \(result.displayVerdict) \(result.riskScore)/100")
        }
    }

    func testFormAttributesCannotBeBorrowedFromNestedMarkup() {
        let page = inspect("<form><input type=password data-action='https://collector.example/'></form>")
        XCTAssertEqual(page.forms.first?.actionHost, "portal.example")
        XCTAssertFalse(page.hasCredentialExternalForm)
    }

    func testUnavailablePartialOrUnsupportedBodyCannotBeClean() {
        let samples = [inspect("", status: 200), inspect("<title>Partial</title>", truncated: true),
                       inspect("binary", type: "application/octet-stream"),
                       inspect("<title>404 TUNNEL NOT FOUND</title>", status: 404)]
        for page in samples {
            let result = engine.applyingPageInspection(engine.scanURL("https://portal.example/"), inspection: page)
            XCTAssertEqual(result.riskLevel, .inconclusive)
            XCTAssertFalse(result.checks?.contains { $0.name == "Page content inspection" && $0.state == .passed } == true)
        }
    }

    func testErrorDocumentCannotMasqueradeAsTheRequestedPhishingPage() {
        let page = inspect(harvestingHTML, status: 404)
        let result = engine.applyingPageInspection(engine.scanURL("https://portal.example/"), inspection: page)
        XCTAssertEqual(result.riskLevel, .inconclusive)
        XCTAssertFalse(page.hasPasswordForm, "The requested page was not available; do not score an error document as that page")
    }

    func testProminentBrandAndWordBoundariesAvoidRegistryOrderAccidents() {
        let page = inspect("<title>PayPal login</title><p>Works with Apple devices</p><form><input type=password></form>")
        XCTAssertTrue(page.evidence.contains { $0.code == "page.brand-impersonation" && $0.title.contains("PayPal") })
        let benign = inspect("<title>Groups login</title><form><input type=password></form>")
        XCTAssertFalse(benign.evidence.contains { $0.code == "page.brand-impersonation" }, "groups is not the UPS brand")
    }
}

// MARK: - Landing-page chain inspection
//
// These fixtures exercise the real page analyzer and merger. They are synthetic
// documents, not captures of a live site, and no fixture contains an expected label
// or a hardcoded verdict.

extension PhishingDetectionRegressionTests {

    func testVisitButtonToBrandLookalikeIsDetectedWithoutFetchingIt() {
        let url = "https://claim-reward.example/"
        let html = """
        <html><head><title>Instagram Giveaway</title></head><body>
        <h1>You have been selected</h1>
        <p>Claim your verified Instagram reward today.</p>
        <button data-href="https://instagram-verification.example/claim">Visit Instagram</button>
        </body></html>
        """
        let page = inspect(html, url: url)
        XCTAssertTrue(page.destinations.contains { $0.source == .button && $0.isExternal })
        XCTAssertTrue(page.evidence.contains { $0.code == "page.misleading-visit-label" },
                      "\(page.evidence.map(\.code))")
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high, "\(result.riskScore) \(result.topEvidence)")
        XCTAssertFalse(result.aiAnalysis != nil)
        print("FIXTURE Visit button → lookalike: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testJavaScriptGeneratedDestinationIsDiscoveredAndExplained() {
        let url = "https://promo.example/"
        let html = """
        <html><head><title>Reward centre</title></head><body>
        <p>Preparing your reward…</p>
        <script>window.location.replace("https://paypal-account-check.example/login");</script>
        </body></html>
        """
        let page = inspect(html, url: url)
        XCTAssertTrue(page.destinations.contains { $0.source == .javascript && $0.host == "paypal-account-check.example" },
                      "\(page.destinations)")
        XCTAssertTrue(page.evidence.contains { $0.code == "page.concealed-navigation" },
                      "\(page.evidence.map(\.code))")
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high, "\(result.riskScore) \(result.topEvidence)")
        print("FIXTURE JavaScript destination: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testBenignLandingPageLinkingToInstagramStaysLow() {
        let url = "https://artist.example/"
        let html = """
        <html><head><title>Studio news</title></head><body>
        <p>Follow the studio for new work.</p>
        <a href="https://www.instagram.com/example_studio/" role="button">Visit Instagram</a>
        </body></html>
        """
        let page = inspect(html, url: url)
        XCTAssertTrue(page.destinations.contains { $0.host == "www.instagram.com" })
        XCTAssertFalse(page.evidence.contains { $0.code == "page.misleading-visit-label" })
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
        XCTAssertEqual(result.riskLevel, .low, "\(result.riskScore) \(result.topEvidence)")
        print("FIXTURE benign Instagram landing: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testLegitimateLoginPageStaysLow() {
        let url = "https://accounts.example.com/"
        let html = """
        <html><head><title>Sign in</title></head><body>
        <form action="/session" method="post">
          <input type="email" name="email"><input type="password" name="password">
          <button>Sign in</button>
        </form></body></html>
        """
        let page = inspect(html, url: url)
        XCTAssertTrue(page.hasPasswordForm)
        XCTAssertFalse(page.hasExternalFormAction)
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
        XCTAssertEqual(result.riskLevel, .low, "\(result.riskScore) \(result.topEvidence)")
        print("FIXTURE legitimate login: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testFetchedFakeLoginDestinationEscalatesWithAttribution() {
        let url = "https://landing.example/"
        let landing = inspect("""
        <title>Reward</title><a href="https://collect.example/verify">Visit</a>
        """, url: url)
        let harvested = inspect("""
        <title>PayPal sign in</title>
        <form action="https://collect.example/steal"><input type="password"></form>
        """, url: "https://collect.example/verify")
        var withDestination = landing
        withDestination.destinationInspections = [DestinationInspection(
            requestedURL: "https://collect.example/verify", finalURL: "https://collect.example/verify",
            httpStatus: 200, title: "PayPal sign in", contentAvailable: true, bodyBytes: 200,
            evidence: harvested.evidence, checks: harvested.checks, limitations: [], hasPasswordForm: true,
            hasPaymentForm: false, hasBrandImpersonation: true,
            hasCredentialExternalForm: harvested.hasCredentialExternalForm)]
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: withDestination)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high)
        XCTAssertTrue(result.evidence.contains { $0.code.hasPrefix("landing.") })
        XCTAssertTrue(result.checks?.contains { $0.name.hasPrefix("Destination ·") } == true)
        print("FIXTURE fetched fake-login destination: \(result.displayVerdict) \(result.riskScore)/100")
    }
}

extension PhishingDetectionRegressionTests {

    func testMessageCheckerKeepsMessageAndURLFindingsDistinct() {
        let message = engine.scanMessage("Urgent: verify your account now at the link below.")
        let page = inspect("""
        <title>PayPal sign in</title>
        <form action="https://collect.example/steal"><input type="password"></form>
        """, url: "https://portal.example/")
        let link = engine.applyingPageInspection(engine.scanURL("https://portal.example/"), inspection: page)
        let merged = engine.mergeLiveLink(into: message, link: link, kind: .message,
                                          prefix: "link.", label: "Link")
        XCTAssertEqual(merged.kind, .message)
        XCTAssertGreaterThanOrEqual(merged.riskLevel ?? .low, .high)
        XCTAssertTrue(merged.evidence.contains { $0.code.hasPrefix("link.page.") },
                      "URL evidence must be visible and attributed: \(merged.evidence.map(\.code))")
        XCTAssertFalse(merged.evidence.contains { $0.code == "page.brand-impersonation" },
                       "Page evidence must not masquerade as message-level evidence")
        XCTAssertEqual(merged.kind, .message,
                       "The merged result must stay a message scan, not become a URL scan")
        print("FIXTURE message + live URL: \(merged.displayVerdict) \(merged.riskScore)/100")
    }

    func testUnreachableDestinationIsReportedNotScoredAsClean() {
        let url = "https://landing.example/"
        var page = inspect("<a href='https://offline.example/visit'>Visit</a>", url: url)
        page.destinationInspections = [DestinationInspection(
            requestedURL: "https://offline.example/visit", finalURL: nil, httpStatus: nil, title: nil,
            contentAvailable: false, bodyBytes: 0, evidence: [],
            checks: [CheckRecord(name: "Destination fetch", state: .failed, detail: "did not resolve")],
            limitations: [], hasPasswordForm: false, hasPaymentForm: false,
            hasBrandImpersonation: false, hasCredentialExternalForm: false)]
        let result = engine.applyingPageInspection(engine.scanURL(url), inspection: page)
        XCTAssertTrue(result.limitations.contains { $0.contains("could not be inspected") })
        XCTAssertTrue(result.checks?.contains { $0.name.hasPrefix("Destination ·") && $0.state == .unavailable } == true)
        XCTAssertNotEqual(result.riskLevel, .high)
    }
}

// MARK: - Domain registration age

extension PhishingDetectionRegressionTests {

    private func registration(minutesAgo: Int?) -> DomainRegistration {
        DomainRegistration(
            registrar: "Fixture Registrar",
            createdAt: minutesAgo.map { Date().addingTimeInterval(-Double($0) * 60) },
            expiresAt: nil, updatedAt: nil, statuses: [], ageDays: minutesAgo.map { $0 / 1440 })
    }

    func testDomainUnderOneHourIsHighlySuspiciousButNotConfirmedPhishing() {
        let age = DomainInspector.assess(registration: registration(minutesAgo: 17),
                                         host: "login.example", registrableDomain: "example")
        XCTAssertTrue(age.evidence.contains { $0.code == "domain.registered-under-1-hour" },
                      "\(age.evidence.map(\.code))")
        XCTAssertFalse(age.failed)
        XCTAssertEqual(age.check.state, .passed)

        let result = engine.applyingDomainAgeReport(engine.scanURL("https://login.example/"), report: age)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high)
        XCTAssertLessThan(result.riskLevel ?? .critical, .critical,
                          "Domain age alone must not confirm phishing")
        XCTAssertGreaterThanOrEqual(result.riskScore, 50)
        XCTAssertTrue(result.evidence.contains { $0.title.localizedCaseInsensitiveContains("highly suspicious") })
        print("FIXTURE 17-minute-old domain: \(result.displayVerdict) \(result.riskScore)/100")
    }

    func testDomainOlderThanOneHourDoesNotTriggerTheOneHourFinding() {
        let age = DomainInspector.assess(registration: registration(minutesAgo: 150),
                                         host: "recent.example", registrableDomain: "example")
        XCTAssertFalse(age.evidence.contains { $0.code == "domain.registered-under-1-hour" })
        XCTAssertTrue(age.evidence.contains { $0.code == "domain.newly-registered" })
        let result = engine.applyingDomainAgeReport(engine.scanURL("https://recent.example/"), report: age)
        XCTAssertLessThan(result.riskLevel ?? .critical, .high)
    }

    func testUnavailableRegistrationAgeIsReportedNotInvented() {
        let age = DomainInspector.assess(registration: registration(minutesAgo: nil),
                                         host: "unknown.example", registrableDomain: "example")
        XCTAssertTrue(age.failed)
        XCTAssertNil(age.ageSeconds)
        XCTAssertEqual(age.check.state, .unavailable)
        XCTAssertTrue(age.limitations.contains { $0.contains("unknown, not a clearance") })

        let result = engine.applyingDomainAgeReport(engine.scanURL("https://unknown.example/"), report: age)
        XCTAssertTrue(result.limitations.contains { $0.contains("unknown, not a clearance") })
        XCTAssertTrue(result.checks?.contains { $0.name == "Domain registration age" && $0.state == .unavailable } == true)
        XCTAssertEqual(result.riskLevel, .inconclusive,
                       "Unavailable registration data must not be presented as a clean low-risk result")
    }
}
