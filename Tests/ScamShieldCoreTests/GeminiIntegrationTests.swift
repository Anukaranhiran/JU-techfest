import Foundation
import XCTest
@testable import ScamShieldCore

// MARK: - Controlled transport

private final class MockAITransport: AIHTTPTransport, @unchecked Sendable {
    typealias Handler = @Sendable (AIHTTPRequest, Int) throws -> AIHTTPResponse

    private let lock = NSLock()
    private var stored: [AIHTTPRequest] = []
    private let handler: Handler

    init(_ handler: @escaping Handler) {
        self.handler = handler
    }

    var requests: [AIHTTPRequest] {
        lock.lock(); defer { lock.unlock() }
        return stored
    }

    var generationRequests: [AIHTTPRequest] {
        requests.filter { $0.url.contains(":generateContent") }
    }

    var discoveryRequests: [AIHTTPRequest] {
        requests.filter { $0.url.contains("/models?") || $0.url.hasSuffix("/models") }
    }

    func send(_ request: AIHTTPRequest) async throws -> AIHTTPResponse {
        lock.lock()
        let index = stored.count
        stored.append(request)
        lock.unlock()
        return try handler(request, index)
    }
}

final class GeminiIntegrationTests: XCTestCase {
    private let key = "test-key-not-a-real-credential"

    // MARK: Fixtures

    private func config(model: String = "",
                        discovered: [GeminiModel] = []) -> AIProviderConfig {
        AIProviderConfig(enabled: true,
                         analysisEnabled: true,
                         provider: .gemini,
                         baseURL: AIProviderKind.gemini.defaultBaseURL,
                         model: model,
                         apiKey: key,
                         discoveredModels: discovered,
                         allowModelFallback: true)
    }

    private func data(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    private func http(_ status: Int, _ body: Data) -> AIHTTPResponse {
        AIHTTPResponse(status: status, body: body, elapsedMs: 1)
    }

    private func modelJSON(_ name: String,
                           methods: [String] = ["generateContent"]) -> String {
        let methodsJSON = methods.map { "\"\($0)\"" }.joined(separator: ",")
        return "{\"name\":\"models/\(name)\",\"displayName\":\"\(name)\",\"supportedGenerationMethods\":[\(methodsJSON)]}"
    }

    private func page(_ entries: [String], next: String? = nil) -> Data {
        let token = next.map { ",\"nextPageToken\":\"\($0)\"" } ?? ""
        return Data("{\"models\":[\(entries.joined(separator: ","))]\(token)}".utf8)
    }

    private func generated(_ text: String) -> Data {
        data(["candidates": [[
            "content": ["parts": [["text": text]]],
            "finishReason": "STOP",
        ]]])
    }

    private func modelError(_ code: Int, _ status: String, _ message: String) -> Data {
        data(["error": ["code": code, "message": message, "status": status]])
    }

    // MARK: 1. Successful model-list decoding

    func testModelListDecodingExtractsNameMethodsAndPaginationToken() throws {
        let body = page([modelJSON("gemini-2.5-flash"),
                         modelJSON("text-embedding-004", methods: ["embedContent"])],
                        next: "next-page")
        let parsed = try XCTUnwrap(GeminiModelDiscovery.parsePage(body))
        XCTAssertEqual(parsed.models.count, 2)
        XCTAssertEqual(parsed.models[0].resourceName, "models/gemini-2.5-flash")
        XCTAssertEqual(parsed.models[0].id, "gemini-2.5-flash")
        XCTAssertTrue(parsed.models[0].supportsGenerateContent)
        XCTAssertEqual(parsed.nextPageToken, "next-page")
    }

    // MARK: 2. Multiple discovery pages

    func testDiscoveryFollowsPaginationAndSendsKeyInHeader() async throws {
        let transport = MockAITransport { request, index in
            XCTAssertEqual(request.headers["x-goog-api-key"], self.key)
            if index == 0 {
                return self.http(200, self.page([
                    self.modelJSON("gemini-2.5-flash"),
                    self.modelJSON("gemini-2.5-pro"),
                ], next: "token-2"))
            }
            XCTAssertTrue(request.url.contains("pageToken=token-2"))
            return self.http(200, self.page([self.modelJSON("gemini-2.5-flash-lite")]))
        }

        let result = await GeminiModelDiscovery.discover(config: config(), transport: transport)
        let report = try XCTUnwrap(try? result.get())
        XCTAssertEqual(report.pagesFetched, 2)
        XCTAssertEqual(report.models.count, 3)
        XCTAssertEqual(report.rawModelCount, 3)
        XCTAssertEqual(transport.discoveryRequests.count, 2)
    }

    // MARK: 3. Filtering incompatible models

    func testFilteringRemovesEmbeddingImageAudioAndAnswerOnlyModels() async throws {
        let transport = MockAITransport { _, _ in
            self.http(200, self.page([
                self.modelJSON("gemini-2.5-flash"),
                self.modelJSON("text-embedding-004", methods: ["embedContent"]),
                self.modelJSON("imagen-4.0-generate-001"),
                self.modelJSON("gemini-2.5-flash-preview-tts"),
                self.modelJSON("gemini-live-2.5-flash-preview"),
                self.modelJSON("aqa"),
                self.modelJSON("gemini-2.5-pro"),
            ]))
        }

        let result = await GeminiModelDiscovery.discover(config: config(), transport: transport)
        let report = try XCTUnwrap(try? result.get())
        XCTAssertEqual(report.models.map(\.id), ["gemini-2.5-flash", "gemini-2.5-pro"],
                       "Only text-generation-capable resources should remain")
        XCTAssertEqual(report.rawModelCount, 7)
    }

    // MARK: 4. Duplicate and malformed entries

    func testDuplicateAndMalformedModelEntriesAreSkipped() async throws {
        let transport = MockAITransport { _, _ in
            let malformed = "{\"name\":123},{\"name\":\"models/a/b\"},{\"name\":\"\"},{\"displayName\":\"no name\"}"
            return self.http(200, self.page([
                self.modelJSON("gemini-2.5-flash"),
                self.modelJSON("gemini-2.5-flash"),
                malformed,
            ]))
        }

        let result = await GeminiModelDiscovery.discover(config: config(), transport: transport)
        let report = try XCTUnwrap(try? result.get())
        XCTAssertEqual(report.models.map(\.id), ["gemini-2.5-flash"])
    }

    // MARK: 5. Successful candidate probing

    func testDiscoveryAndSelectionProbeARealGenerateContentResponse() async throws {
        let transport = MockAITransport { request, _ in
            if request.url.contains(":generateContent") {
                XCTAssertEqual(request.method, "POST")
                XCTAssertEqual(request.headers["x-goog-api-key"], self.key)
                XCTAssertFalse(request.url.contains(self.key), "Key must not be in the URL")
                return self.http(200, self.generated("READY"))
            }
            return self.http(200, self.page([
                self.modelJSON("gemini-2.0-flash"),
                self.modelJSON("gemini-2.5-flash"),
            ]))
        }

        let result = await GeminiModelSelector.discoverAndSelect(
            config: config(), transport: transport)
        let selection = try XCTUnwrap(try? result.get())
        XCTAssertEqual(selection.model.id, "gemini-2.5-flash")
        XCTAssertEqual(selection.probed, ["gemini-2.5-flash"])
        XCTAssertEqual(transport.discoveryRequests.count, 1)
        XCTAssertEqual(transport.generationRequests.count, 1)
        XCTAssertTrue(transport.generationRequests[0].url.contains("/models/gemini-2.5-flash:generateContent"))
    }

    // MARK: 6. First candidate fails, second works

    func testFirstCandidateFailureFallsThroughToNextCandidate() async throws {
        let transport = MockAITransport { request, _ in
            if request.url.contains("flash:generateContent") {
                return self.http(404, self.modelError(
                    404, "NOT_FOUND", "models/gemini-2.5-flash is not found for this key"))
            }
            if request.url.contains("pro:generateContent") {
                return self.http(200, self.generated("READY"))
            }
            return self.http(200, self.page([
                self.modelJSON("gemini-2.5-flash"),
                self.modelJSON("gemini-2.5-pro"),
            ]))
        }

        let result = await GeminiModelSelector.discoverAndSelect(
            config: config(), transport: transport)
        let selection = try XCTUnwrap(try? result.get())
        XCTAssertEqual(selection.model.id, "gemini-2.5-pro")
        XCTAssertEqual(selection.probed, ["gemini-2.5-flash", "gemini-2.5-pro"])
        XCTAssertEqual(transport.generationRequests.count, 2)
    }

    // MARK: 7. Invalid API key

    func testInvalidAPIKeyIsClassifiedAndStopsDiscovery() async throws {
        let transport = MockAITransport { _, _ in
            self.http(400, self.modelError(
                400, "INVALID_ARGUMENT", "API key not valid. Please pass a valid API key."))
        }
        let result = await GeminiModelDiscovery.discover(config: config(), transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected failure")
        }
        XCTAssertEqual(error, .invalidAPIKey)
        XCTAssertTrue(error.isTerminalForProbing)
    }

    // MARK: 8. Permission denied is not an invalid key

    func testPermissionDeniedIsNotReportedAsInvalidKey() {
        let failure = AIProviderErrorClassifier.classify(
            status: 403,
            body: modelError(403, "PERMISSION_DENIED",
                             "The caller does not have permission to use this model."),
            secrets: [key])
        guard case .permissionDenied(let detail) = failure else {
            return XCTFail("Expected permissionDenied, got \(failure)")
        }
        XCTAssertFalse(detail.lowercased().contains("api key not valid"))
    }

    // MARK: 9. Model unavailable

    func testModelUnavailableIsClassifiedFromStructuredError() {
        let failure = AIProviderErrorClassifier.classify(
            status: 404,
            body: modelError(404, "NOT_FOUND", "models/retired-model is not found"),
            secrets: [key])
        guard case .modelUnavailable = failure else {
            return XCTFail("Expected modelUnavailable, got \(failure)")
        }
    }

    // MARK: 10. Rate limiting and quota exhaustion

    func testRateLimitAndQuotaExhaustionAreDistinct() {
        let rate = AIProviderErrorClassifier.classify(
            status: 429,
            body: modelError(429, "RESOURCE_EXHAUSTED",
                             "Resource has been exhausted (e.g. check quota)."),
            secrets: [key])
        XCTAssertEqual(rate, .rateLimited)

        let quota = AIProviderErrorClassifier.classify(
            status: 429,
            body: modelError(429, "RESOURCE_EXHAUSTED",
                             "You exceeded your current quota, please check your plan and billing details."),
            secrets: [key])
        guard case .quotaExhausted = quota else {
            return XCTFail("Expected quotaExhausted, got \(quota)")
        }
    }

    func testQuotaExhaustionStopsModelProbingAfterOneRequest() async throws {
        let transport = MockAITransport { request, _ in
            if request.url.contains(":generateContent") {
                return self.http(429, self.modelError(
                    429, "RESOURCE_EXHAUSTED",
                    "You exceeded your current quota for this project."))
            }
            return self.http(200, self.page([
                self.modelJSON("gemini-2.5-flash"),
                self.modelJSON("gemini-2.5-pro"),
                self.modelJSON("gemini-2.0-flash"),
            ]))
        }

        let result = await GeminiModelSelector.discoverAndSelect(
            config: config(), transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected quota failure")
        }
        guard case .quotaExhausted = error else {
            return XCTFail("Expected quotaExhausted, got \(error)")
        }
        XCTAssertEqual(transport.generationRequests.count, 1,
                       "A quota-exhausted request must not be retried against every model")
    }

    // MARK: 11. Network timeout

    func testNetworkTimeoutIsReportedAndDoesNotBecomeASuccess() async throws {
        let transport = MockAITransport { _, _ in
            throw SafeNetworkError(kind: .timeout, detail: "timed out")
        }
        let result = await GeminiModelDiscovery.discover(config: config(), transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected timeout failure")
        }
        XCTAssertEqual(error, .timeout)
    }

    // MARK: 12. Malformed generation response

    func testMalformedGenerationResponseIsInvalidNotClean() async throws {
        let transport = MockAITransport { _, _ in
            self.http(200, Data("this is not JSON".utf8))
        }
        let result = await AIProviderClient.completeDetailed(
            system: "system", user: "user", config: config(model: "gemini-2.5-flash"),
            expectJSON: true, transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected malformed response failure")
        }
        guard case .invalidResponse = error else {
            return XCTFail("Expected invalidResponse, got \(error)")
        }
    }

    // MARK: 13. Empty generated content

    func testEmptyGeneratedContentIsRejected() async throws {
        let body = data(["candidates": [[
            "content": ["parts": []],
            "finishReason": "STOP",
        ]]])
        let transport = MockAITransport { _, _ in self.http(200, body) }
        let result = await AIProviderClient.completeDetailed(
            system: "system", user: "user", config: config(model: "gemini-2.5-flash"),
            expectJSON: true, transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected empty response failure")
        }
        XCTAssertEqual(error, .emptyResponse)
    }

    func testSafetyBlockedContentIsReportedAsBlocked() async throws {
        let body = data(["candidates": [[
            "content": ["parts": []],
            "finishReason": "SAFETY",
        ]]])
        let transport = MockAITransport { _, _ in self.http(200, body) }
        let result = await AIProviderClient.completeDetailed(
            system: "system", user: "user", config: config(model: "gemini-2.5-flash"),
            expectJSON: true, transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected blocked response failure")
        }
        guard case .contentBlocked = error else {
            return XCTFail("Expected contentBlocked, got \(error)")
        }
    }

    // MARK: 14. API key change invalidates stale selection

    func testAPIKeyChangeInvalidatesCachedSelection() {
        let cache = AISelectionCache(
            modelID: "gemini-2.5-flash",
            resourceName: "models/gemini-2.5-flash",
            discoveredAt: Date(),
            verifiedAt: Date(),
            keyFingerprint: AISecretFingerprint.fingerprint("old-key"))
        XCTAssertTrue(cache.isValid(apiKey: "old-key"))
        XCTAssertFalse(cache.isValid(apiKey: "new-key"))
        XCTAssertFalse(cache.isValid(apiKey: "old-key", now: Date().addingTimeInterval(31 * 24 * 60 * 60)))
    }

    // MARK: 15. Cached selection and rediscovery

    func testCachedAlternativeIsUsedWithoutRediscovery() async throws {
        let cached = GeminiModel(
            resourceName: "models/gemini-2.5-pro",
            supportedGenerationMethods: ["generateContent"])
        let transport = MockAITransport { request, _ in
            if request.url.contains("/models?") || request.url.hasSuffix("/models") {
                XCTFail("Discovery must not run when a cached alternative exists")
                return self.http(500, Data())
            }
            if request.url.contains("flash:generateContent") {
                return self.http(404, self.modelError(404, "NOT_FOUND", "model not found"))
            }
            return self.http(200, self.generated("READY"))
        }

        let result = await AIProviderClient.completeWithFallback(
            system: "system", user: "user",
            config: config(model: "gemini-2.5-flash", discovered: [cached]),
            expectJSON: false, transport: transport)
        let completion = try XCTUnwrap(try? result.get())
        XCTAssertEqual(completion.modelID, "gemini-2.5-pro")
        XCTAssertTrue(transport.discoveryRequests.isEmpty)
    }

    func testUnavailableSelectedModelTriggersOneRediscoveryAndFallback() async throws {
        let transport = MockAITransport { request, _ in
            if request.url.contains("/models?") || request.url.hasSuffix("/models") {
                return self.http(200, self.page([self.modelJSON("gemini-2.5-pro")]))
            }
            if request.url.contains("flash:generateContent") {
                return self.http(404, self.modelError(404, "NOT_FOUND", "model retired"))
            }
            return self.http(200, self.generated("READY"))
        }

        let result = await AIProviderClient.completeWithFallback(
            system: "system", user: "user",
            config: config(model: "gemini-2.5-flash"),
            expectJSON: false, transport: transport)
        let completion = try XCTUnwrap(try? result.get())
        XCTAssertEqual(completion.modelID, "gemini-2.5-pro")
        XCTAssertEqual(transport.discoveryRequests.count, 1)
    }

    // MARK: 16. No compatible models

    func testNoCompatibleModelsIsExplicit() async throws {
        let transport = MockAITransport { _, _ in
            self.http(200, self.page([
                self.modelJSON("text-embedding-004", methods: ["embedContent"]),
                self.modelJSON("imagen-4.0-generate-001"),
            ]))
        }
        let result = await GeminiModelSelector.discoverAndSelect(
            config: config(), transport: transport)
        guard case .failure(let error) = result else {
            return XCTFail("Expected noCompatibleModels")
        }
        XCTAssertEqual(error, .noCompatibleModels)
        XCTAssertTrue(transport.generationRequests.isEmpty)
    }

    // MARK: 17. Secret redaction

    func testSecretsAreRedactedFromErrorsAndDescriptions() {
        let secret = "sk-super-secret-key-123"
        let body = modelError(
            400, "INVALID_ARGUMENT",
            "API key not valid: \(secret) AIzaSyExampleKeyValue1234567890 key=\(secret)")
        let failure = AIProviderErrorClassifier.classify(status: 400, body: body, secrets: [secret])
        let description = failure.errorDescription ?? ""
        XCTAssertFalse(description.contains(secret))
        XCTAssertFalse(description.contains("AIzaSyExampleKeyValue"))
        XCTAssertTrue(description.contains("invalid") || description.contains("rejected"))
    }

    // MARK: No compiled-in Gemini default

    func testGeminiWithoutDiscoveredModelIsNotConfigured() {
        let unselected = config(model: "")
        XCTAssertEqual(unselected.resolvedModel, "",
                       "Gemini must not fall back to a hardcoded model name")
        XCTAssertFalse(unselected.hasCredentials)
        XCTAssertFalse(unselected.isConfigured)
    }

    // MARK: Endpoint normalization

    func testModelResourceNameIsNormalizedAndPathEncoded() throws {
        let resource = AIProviderConfig(provider: .gemini,
                                        baseURL: "https://generativelanguage.googleapis.com/v1beta",
                                        model: "models/gemini-2.5-flash",
                                        apiKey: "k")
        XCTAssertEqual(try XCTUnwrap(AIProviderClient.endpoint(for: resource)).absoluteString,
                       "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent")

        let baseWithModels = AIProviderConfig(provider: .gemini,
                                              baseURL: "https://generativelanguage.googleapis.com/v1beta/models",
                                              model: "gemini-2.5-pro",
                                              apiKey: "k")
        XCTAssertEqual(try XCTUnwrap(AIProviderClient.endpoint(for: baseWithModels)).absoluteString,
                       "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent")
    }

    // MARK: 18. Gemini explanation cannot change the deterministic verdict

    func testGeminiExplanationCannotDowngradeDeterministicVerdict() {
        let engine = ScanEngine()
        var high = engine.scanURL("https://random123456.loclx.io/login")
        high.riskLevel = .high
        high.riskScore = 72
        high.evidence.append(Evidence(
            code: "deterministic.fixture",
            title: "Off-domain password collection",
            detail: "A credential form posts to a different registrable domain.",
            weight: 40, category: .content))
        let priorLevel = high.riskLevel

        let report = AIAnalysisReport(
            provider: AIProviderKind.gemini.title,
            model: "gemini-2.5-flash",
            assessment: .none, confidence: .high,
            summary: "No additional suspicious pattern was found.",
            findings: [], limitations: [], elapsedMs: 12)
        let merged = engine.applyingAIAnalysis(high, report: report)
        XCTAssertGreaterThanOrEqual(merged.riskLevel ?? .low, priorLevel ?? .low)
        XCTAssertTrue(merged.evidence.contains { $0.code == "deterministic.fixture" },
                      "AI must not erase deterministic evidence")
        XCTAssertEqual(merged.aiAnalysis?.model, "gemini-2.5-flash")
    }
}
