import XCTest
@testable import ScamShieldCore

final class ScannerTests: XCTestCase {

    let engine = ScanEngine()

    // MARK: - Benign control group must stay low

    func testOfficialSitesAreLowRisk() {
        let urls = [
            "https://www.apple.com/support/",
            "https://www.paypal.com/signin",
            "https://login.microsoftonline.com/",
            "https://www.amazon.com/gp/your-account/order-history",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://github.com/apple/swift",
        ]
        for url in urls {
            let result = engine.scanURL(url)
            XCTAssertEqual(result.status, .complete, url)
            XCTAssertEqual(result.riskLevel, .low, "\(url) → \(result.displayVerdict) \(result.topEvidence.map(\.title))")
        }
    }

    func testLocalAndPrivateAddressesAreContextualisedNotMalicious() {
        let local = engine.scanURL("http://localhost:3000/dashboard")
        XCTAssertEqual(local.riskLevel, .low)
        XCTAssertTrue(local.evidence.contains { $0.code == "context.localhost" })

        let privateIP = engine.scanURL("http://192.168.1.1/admin")
        XCTAssertEqual(privateIP.riskLevel, .low)
        XCTAssertTrue(privateIP.evidence.contains { $0.code == "context.private-network" })

        // Same shape on the public internet must not be treated as local.
        let publicIP = engine.scanURL("http://203.0.113.45/admin")
        XCTAssertNotEqual(publicIP.riskLevel, .low)
    }

    // MARK: - Suspicious shapes

    func testBrandImpersonationFamilies() {
        let cases: [(String, RiskLevel)] = [
            ("https://appleid-apple.com-verify-account.tk/login/confirm", .high),
            ("https://paypa1.com/login", .medium),
            ("http://paypal.com.secure-login.workers.dev/session", .high),
            ("https://amaz0n-account-verify.shop/", .high),
            ("https://www.\u{0430}pple.com/verify", .high),
        ]
        for (url, minimum) in cases {
            let result = engine.scanURL(url)
            guard let level = result.riskLevel else {
                XCTFail("no verdict for \(url)"); continue
            }
            XCTAssertGreaterThanOrEqual(level, minimum, "\(url) → \(result.riskScore) \(result.topEvidence.map(\.title))")
        }
    }

    func testDangerousSchemesAreBlocked() {
        let js = engine.scanURL("javascript:alert(document.cookie)")
        XCTAssertEqual(js.riskLevel, .critical)

        let data = engine.scanURL("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        XCTAssertEqual(data.riskLevel, .critical)
        XCTAssertTrue(data.limitations.first?.contains("never handed") == true)
    }

    func testOpenRedirectIsNestedScanned() {
        let result = engine.scanURL("https://example.com/redirect?url=https://evil-login.tk/account/verify")
        XCTAssertNotNil(result.riskLevel)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium)
    }

    func testShortenerCannotBeCalledSafe() {
        let result = engine.scanURL("https://bit.ly/3xYzAbC")
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium)
        XCTAssertTrue(result.isVerified)
        XCTAssertTrue(result.limitations.contains { $0.lowercased().contains("shortener") })
    }

    // MARK: - Failure paths must never be safe

    func testEmptyInputIsUnverified() {
        let result = engine.scanURL("   ")
        XCTAssertEqual(result.status, .failed)
        XCTAssertNil(result.riskLevel)
        XCTAssertEqual(result.displayVerdict, "UNVERIFIED")
    }

    func testNonURITextIsUnverified() {
        // Free text must be rejected, not coerced into a host and then called low risk.
        let result = engine.scanURL("not a url at all")
        XCTAssertEqual(result.status, .failed)
        XCTAssertNil(result.riskLevel)
        XCTAssertEqual(result.displayVerdict, "UNVERIFIED")
    }

    func testReputationFailureNeverUpgradesVerdict() {
        let base = engine.scanURL("https://paypa1.com/login")
        let withError = engine.applyingReputation(base, outcome: ReputationOutcome(status: .error, detail: "timeout"))
        XCTAssertEqual(withError.riskLevel, base.riskLevel)
        XCTAssertTrue(withError.limitations.contains { $0.contains("lookup failed") })
        XCTAssertTrue(withError.skippedChecks.contains { $0.contains("not a clearance") })

        let unknown = engine.applyingReputation(base, outcome: ReputationOutcome(status: .unknown, detail: "no data"))
        XCTAssertNotNil(unknown.riskLevel)
        XCTAssertGreaterThanOrEqual(unknown.riskLevel ?? .low, base.riskLevel ?? .low)
    }

    func testMaliciousReputationEscalates() {
        let base = engine.scanURL("https://some-unknown-host.example/path")
        let escalated = engine.applyingReputation(base, outcome: ReputationOutcome(status: .malicious, detail: "matched test list"))
        XCTAssertGreaterThan(escalated.riskScore, base.riskScore)
        XCTAssertEqual(escalated.riskLevel, .critical)
    }

    // MARK: - Message and email analysis

    func testOTPRequestIsCaught() {
        let result = engine.scanMessage("This is Apple support. Send me the 6-digit verification code within 24 hours or your account will be locked.")
        XCTAssertNotNil(result.riskLevel)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium)
        XCTAssertTrue(result.evidence.contains { $0.code.contains("otp") || $0.code.contains("text.otp") })
    }

    func testRemoteAccessRequestIsHighSignal() {
        let result = engine.scanMessage("Hi, I am from Microsoft support. Install AnyDesk and allow remote access so I can fix your Mac.")
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium)
    }

    func testSpoofedEmailHitsEveryHeaderSignal() {
        let raw = """
        From: Apple Support <no-reply@apple-security-alert.tk>
        Reply-To: help@mailbox-verify.ru
        Return-Path: <bounce@mailbox-verify.ru>
        Subject: Your Apple ID has been suspended
        Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=apple-security-alert.tk; dkim=fail; dmarc=fail

        Your account will be suspended within 24 hours. Verify your account now:
        http://apple-security-alert.tk/verify-account?session=8812
        """
        let result = engine.scanEmail(raw)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .high)
        let codes = result.evidence.map(\.code)
        XCTAssertTrue(codes.contains("email.display-name-spoof"))
        XCTAssertTrue(codes.contains("email.reply-to-mismatch"))
        XCTAssertTrue(codes.contains { $0.contains("auth-spf") || $0.contains("auth-dkim") })
    }

    func testAuthenticatedOfficialEmailStaysLow() {
        let raw = """
        From: Chase Online <no-reply@chase.com>
        Reply-To: no-reply@chase.com
        Return-Path: <no-reply@chase.com>
        Subject: Your monthly statement is ready
        Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=chase.com; dkim=pass; dmarc=pass

        Your statement is available at https://www.chase.com/statements
        """
        let result = engine.scanEmail(raw)
        XCTAssertEqual(result.riskLevel, .low, "\(result.topEvidence.map(\.title))")
    }

    func testEmailWithoutAuthHeadersSaysSo() {
        let result = engine.scanEmail("From: Someone <a@example.com>\nSubject: hello\n\nHi there.")
        XCTAssertTrue(result.skippedChecks.contains { $0.contains("Authentication-Results") })
    }

    // MARK: - Parsing units

    func testRegistrableDomain() {
        XCTAssertEqual(DomainUtils.registrableDomain("a.b.example.co.uk"), "example.co.uk")
        XCTAssertEqual(DomainUtils.registrableDomain("www.apple.com"), "apple.com")
        XCTAssertEqual(DomainUtils.registrableDomain("192.168.1.1"), "192.168.1.1")
        XCTAssertEqual(DomainUtils.registrableDomain("paypal.com.evil.tk"), "evil.tk")
    }

    func testPunycodeDecoder() {
        XCTAssertEqual(Punycode.decodeLabel("xn--bcher-kva"), "bücher")
        XCTAssertEqual(Punycode.decodeLabel("xn--pple-43d"), "\u{0430}pple")
        XCTAssertNil(Punycode.decodeLabel("apple"))
        XCTAssertEqual(Punycode.decodeHost("www.xn--bcher-kva.de"), "www.bücher.de")
    }

    func testURLParsingKeepsDangerousParts() throws {
        let url = try ParsedURL.parse("https://apple.com:8443@evil.tk:9999/a?b=c#d")
        XCTAssertEqual(url.host, "evil.tk")
        XCTAssertEqual(url.port, 9999)
        XCTAssertEqual(url.userInfo, "apple.com:8443")
        XCTAssertEqual(url.registrableDomain, "evil.tk")
    }

    func testEvidenceIsDeterministic() {
        let a = engine.scanURL("https://paypa1.com/login")
        let b = engine.scanURL("https://paypa1.com/login")
        XCTAssertEqual(a.riskScore, b.riskScore)
        XCTAssertEqual(a.evidence.map(\.code), b.evidence.map(\.code))
    }
}
