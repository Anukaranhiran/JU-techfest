import XCTest
import AppKit
import ImageIO
import UniformTypeIdentifiers
@testable import ScamShieldCore

final class MediaStorageTests: XCTestCase {

    let engine = ScanEngine()

    // MARK: - QR

    func pngData(from image: CGImage) -> Data? {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
    }

    func testQRCodeRoundTripIsScanned() throws {
        let url = "https://paypa1.com/login"
        guard let image = MediaAnalyzer.generateQRCode(url), let data = pngData(from: image) else {
            return XCTFail("could not render a QR code")
        }
        let result = engine.scanQRImage(data)
        XCTAssertEqual(result.kind, .qr)
        XCTAssertEqual(result.status, .complete)
        XCTAssertEqual(result.analyzedURL?.contains("paypa1.com"), true, "\(result.analyzedURL ?? "nil")")
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium)
        XCTAssertTrue(result.limitations.contains { $0.contains("Decoded") })
    }

    func testBenignQRCodeStaysLow() throws {
        guard let image = MediaAnalyzer.generateQRCode("https://www.apple.com/support/"),
              let data = pngData(from: image) else {
            return XCTFail("could not render a QR code")
        }
        let result = engine.scanQRImage(data)
        XCTAssertEqual(result.riskLevel, .low)
    }

    func testImageWithoutQRCodeIsUnverified() throws {
        let image = NSImage(size: NSSize(width: 64, height: 64))
        image.lockFocus()
        NSColor.white.setFill()
        NSRect(x: 0, y: 0, width: 64, height: 64).fill()
        image.unlockFocus()
        guard let tiff = image.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else {
            return XCTFail("could not render blank image")
        }
        let result = engine.scanQRImage(png)
        XCTAssertEqual(result.status, .failed)
        XCTAssertNil(result.riskLevel)
        XCTAssertEqual(result.displayVerdict, "UNVERIFIED")
    }

    // MARK: - OCR

    func testScreenshotOCRReadsScamText() throws {
        let text = "URGENT: your account is suspended.\nVerify at https://paypa1.com/login within 24 hours."
        let size = NSSize(width: 900, height: 220)
        let image = NSImage(size: size)
        image.lockFocus()
        NSColor.white.setFill()
        NSRect(origin: .zero, size: size).fill()
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 26),
            .foregroundColor: NSColor.black,
        ]
        (text as NSString).draw(in: NSRect(x: 20, y: 40, width: 860, height: 150), withAttributes: attrs)
        image.unlockFocus()

        guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else {
            return XCTFail("could not render screenshot")
        }
        let result = engine.scanScreenshot(png)
        if result.status != .complete {
            throw XCTSkip("Vision OCR unavailable in this environment: \(result.limitations)")
        }
        XCTAssertEqual(result.kind, .screenshot)
        XCTAssertGreaterThanOrEqual(result.riskLevel ?? .low, .medium, "OCR text: \(result.input)")
    }

    // MARK: - Storage

    func makeTempStore() -> HistoryStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scamshield-test-\(UUID().uuidString).jsonl")
        return HistoryStore(fileURL: url)
    }

    func testHistoryPersistsAndReloads() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scamshield-test-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }

        let store = HistoryStore(fileURL: url)
        let scan = engine.scanURL("https://paypa1.com/login")
        store.append(HistoryEntry(scan: scan, action: ActionRecord(action: .cancelled, note: "user cancelled"), source: "LaunchServices"))
        XCTAssertEqual(store.count, 1)

        let reloaded = HistoryStore(fileURL: url)
        XCTAssertEqual(reloaded.count, 1)
        XCTAssertEqual(reloaded.all().first?.action?.action, .cancelled)
        XCTAssertEqual(reloaded.all().first?.scan.analyzedURL, scan.analyzedURL)
    }

    func testHistoryFiltering() {
        let store = makeTempStore()
        let low = engine.scanURL("https://www.apple.com/support/")
        let high = engine.scanURL("https://appleid-apple.com-verify-account.tk/login/confirm")
        store.append(HistoryEntry(scan: low))
        store.append(HistoryEntry(scan: high, action: ActionRecord(action: .cancelled)))

        var filter = HistoryFilter()
        filter.onlyBlocked = true
        XCTAssertEqual(store.entries(filter: filter).count, 1)

        filter = HistoryFilter()
        filter.levels = [.high, .critical]
        XCTAssertEqual(store.entries(filter: filter).count, 1)

        filter = HistoryFilter()
        filter.search = "appleid"
        XCTAssertEqual(store.entries(filter: filter).count, 1)
    }

    func testExportsProduceContent() throws {
        let store = makeTempStore()
        store.append(HistoryEntry(scan: engine.scanURL("https://paypa1.com/login"),
                                  action: ActionRecord(action: .openedAnyway)))
        let csv = try store.export(format: .csv, entries: store.all())
        XCTAssertTrue(String(data: csv, encoding: .utf8)?.contains("paypa1.com") == true)
        let md = try store.export(format: .markdown, entries: store.all())
        XCTAssertTrue(String(data: md, encoding: .utf8)?.contains("# ScamShield report") == true)
        let json = try store.export(format: .json, entries: store.all())
        XCTAssertFalse(json.isEmpty)
    }

    func testAllowlistMatching() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scamshield-allow-\(UUID().uuidString).json")
        let store = AllowlistStore(fileURL: url)
        store.add(domain: "example.com", durationDays: 30)
        XCTAssertTrue(store.isAllowed(host: "example.com"))
        XCTAssertTrue(store.isAllowed(host: "mail.example.com"))
        XCTAssertFalse(store.isAllowed(host: "notexample.com"))
        store.add(domain: "expired.com", durationDays: -1)
        XCTAssertFalse(store.isAllowed(host: "expired.com"))
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Intel

    func testIntelGraphOnlyLinksObservedData() {
        let a = engine.scanURL("https://paypa1.com/login")
        let b = engine.scanURL("https://paypa1-secure.tk/verify-account")
        let entries = [HistoryEntry(scan: a), HistoryEntry(scan: b)]
        let graph = IntelBuilder.build(from: entries)

        XCTAssertEqual(graph.scansConsidered, 2)
        XCTAssertTrue(graph.nodes.contains { $0.kind == .domain && $0.label == "paypa1.com" })
        XCTAssertTrue(graph.nodes.contains { $0.kind == .domain && $0.label == "paypa1-secure.tk" })
        // Every edge must point at a node that exists (no invented links).
        let ids = Set(graph.nodes.map(\.id))
        for edge in graph.edges {
            XCTAssertTrue(ids.contains(edge.source), "dangling edge source \(edge.source)")
            XCTAssertTrue(ids.contains(edge.target), "dangling edge target \(edge.target)")
        }
        XCTAssertTrue(graph.disclaimer.contains("not proof"))
    }

    func testEmptyIntelGraphIsHonest() {
        let graph = IntelBuilder.build(from: [])
        XCTAssertTrue(graph.nodes.isEmpty)
        XCTAssertTrue(graph.clusters.isEmpty)
        XCTAssertEqual(graph.scansConsidered, 0)
    }

    // MARK: - Evaluation gate

    func testBuiltInFixturesHaveNoFalsePositivesOrNegatives() {
        let run = EvaluationRunner(engine: engine).runBuiltIn()
        XCTAssertEqual(run.falsePositives, 0, "\(run.failures)")
        XCTAssertEqual(run.falseNegatives, 0, "\(run.failures)")
        XCTAssertEqual(run.total, FixtureLibrary.fixtures.count)
        XCTAssertGreaterThan(run.total, 20)
    }
}
