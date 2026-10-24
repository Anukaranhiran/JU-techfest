import Foundation

// MARK: - Safe outbound HTTP
//
// Every network request ScamShield makes on the user's behalf goes through this file.
// It exists to stop the scanner being turned into a server-side request forgery tool:
// loopback, private, link-local, CGNAT, reserved and cloud-metadata addresses are
// rejected before a connection is attempted, and the destination is re-validated on
// every redirect. TLS verification is always on; content is untrusted bytes.

public struct SafeHTTPResponse: Sendable {
    public var requestedURL: String
    public var finalURL: String
    public var status: Int
    public var headers: [String: String]
    public var body: Data
    public var redirects: [RedirectHop]
    public var truncated: Bool
    public var elapsedMs: Double

    public init(requestedURL: String, finalURL: String, status: Int,
                headers: [String: String], body: Data, redirects: [RedirectHop],
                truncated: Bool, elapsedMs: Double) {
        self.requestedURL = requestedURL
        self.finalURL = finalURL
        self.status = status
        self.headers = headers
        self.body = body
        self.redirects = redirects
        self.truncated = truncated
        self.elapsedMs = elapsedMs
    }

    public var bodyText: String {
        String(data: body, encoding: .utf8) ?? String(decoding: body, as: UTF8.self)
    }

    public var contentType: String { headers["content-type"] ?? "" }
}

public struct RedirectHop: Codable, Sendable, Hashable, Identifiable {
    public var from: String
    public var to: String
    public var status: Int
    public var id: String { from + "->" + to + ":" + String(status) }
}

public struct SafeNetworkError: LocalizedError, Sendable {
    public enum Kind: String, Sendable {
        case invalidURL
        case blockedPort
        case blockedAddress
        case resolutionFailed
        case tooManyRedirects
        case timeout
        case tooLarge
        case transport
        case notHTML
    }

    public let kind: Kind
    public let detail: String

    public init(kind: Kind, detail: String) {
        self.kind = kind
        self.detail = detail
    }

    public var errorDescription: String? { detail }
}

public enum SafeAddressPolicy {
    /// Only ordinary web ports. Anything else is rejected rather than probed.
    public static let allowedPorts: Set<Int> = [80, 443, 8080, 8443]

    public static func validateURL(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw SafeNetworkError(kind: .invalidURL, detail: "Only http:// and https:// can be fetched.")
        }
        guard let host = url.host, !host.isEmpty else {
            throw SafeNetworkError(kind: .invalidURL, detail: "The URL has no host.")
        }
        if let port = url.port, !allowedPorts.contains(port) {
            throw SafeNetworkError(kind: .blockedPort,
                                   detail: "Port \(port) is not an allowed web port. ScamShield only fetches 80, 443, 8080 and 8443.")
        }
        if DomainUtils.isBlockedDestination(host) {
            throw SafeNetworkError(kind: .blockedAddress,
                                   detail: "\(host) is a loopback, private, link-local, metadata or reserved address. ScamShield will not fetch it.")
        }
        // A literal IP is checked above. For names, resolve now and reject if *any*
        // returned address is internal. This also blocks a name that currently points
        // at localhost (a common DNS-rebinding setup).
        if !DomainUtils.isIPAddress(host) {
            let addresses = HostResolver.resolve(host)
            guard !addresses.isEmpty else {
                throw SafeNetworkError(kind: .resolutionFailed,
                                       detail: "\(host) did not resolve. The destination may be offline or newly created.")
            }
            for address in addresses where DomainUtils.isBlockedDestination(address) {
                throw SafeNetworkError(kind: .blockedAddress,
                                       detail: "\(host) resolves to \(address), which is a private, loopback, link-local or reserved address. Refusing to connect.")
            }
        }
    }
}

public enum HostResolver {
    /// Blocking getaddrinfo. Returns numeric address strings (IPv4 and IPv6).
    public static func resolve(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        hints.ai_family = AF_UNSPEC
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let first = result else { return [] }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            defer { cursor = info.pointee.ai_next }
            guard let sockaddrPointer = info.pointee.ai_addr else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sockaddrPointer, info.pointee.ai_addrlen,
                           &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let address = String(cString: buffer)
                if !address.isEmpty, !addresses.contains(address) { addresses.append(address) }
            }
        }
        return addresses
    }
}

final class SafeSessionDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let maxBytes: Int
    private let maxRedirects: Int
    private var hops: [RedirectHop] = []
    private var data = Data()
    private var truncated = false
    private var blocked: SafeNetworkError?
    private var finished = false
    private var completion: ((Result<(Data, Bool, URLResponse), Error>) -> Void)?

    init(maxBytes: Int, maxRedirects: Int) {
        self.maxBytes = maxBytes
        self.maxRedirects = maxRedirects
    }

    func attach(_ completion: @escaping (Result<(Data, Bool, URLResponse), Error>) -> Void) {
        lock.lock(); self.completion = completion; lock.unlock()
    }

    var redirects: [RedirectHop] {
        lock.lock(); defer { lock.unlock() }
        return hops
    }

    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        lock.lock()
        let count = hops.count
        lock.unlock()
        guard count < maxRedirects else {
            lock.lock()
            blocked = SafeNetworkError(kind: .tooManyRedirects,
                                       detail: "The server redirected more than \(maxRedirects) times. ScamShield stopped following.")
            lock.unlock()
            completionHandler(nil)
            return
        }
        guard let target = request.url else { completionHandler(nil); return }
        do {
            try SafeAddressPolicy.validateURL(target)
        } catch {
            lock.lock()
            blocked = (error as? SafeNetworkError) ?? SafeNetworkError(kind: .blockedAddress, detail: error.localizedDescription)
            lock.unlock()
            completionHandler(nil)
            return
        }
        lock.lock()
        hops.append(RedirectHop(from: response.url?.absoluteString ?? "",
                                to: target.absoluteString,
                                status: response.statusCode))
        lock.unlock()
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        lock.lock()
        if data.count >= maxBytes {
            truncated = true
            lock.unlock()
            dataTask.cancel()
            return
        }
        let remaining = maxBytes - data.count
        if chunk.count > remaining {
            data.append(chunk.prefix(remaining))
            truncated = true
            lock.unlock()
            dataTask.cancel()
        } else {
            data.append(chunk)
            lock.unlock()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let done = completion
        completion = nil
        let body = data
        let wasTruncated = truncated
        let refusal = blocked
        lock.unlock()
        guard let done else { return }
        if let refusal {
            done(.failure(refusal))
        } else if let error, !wasTruncated {
            done(.failure(error))
        } else if let response = task.response {
            done(.success((body, wasTruncated, response)))
        } else {
            done(.failure(SafeNetworkError(kind: .transport, detail: "The destination did not return a response.")))
        }
    }
}

public enum SafeFetcher {

    public static func fetch(
        _ urlString: String,
        method: String = "GET",
        maxRedirects: Int = 5,
        timeout: TimeInterval = 8,
        maxBytes: Int = 512 * 1024,
        extraHeaders: [String: String] = [:],
        body: Data? = nil
    ) async throws -> SafeHTTPResponse {
        let started = Date()
        guard let url = URL(string: urlString) else {
            throw SafeNetworkError(kind: .invalidURL, detail: "“\(urlString)” is not a valid URL.")
        }
        try SafeAddressPolicy.validateURL(url)

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout + 2
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.waitsForConnectivity = false
        config.httpAdditionalHeaders = [
            "User-Agent": "ScamShield/1.1 (security inspection)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
            "Accept-Language": "en",
        ].merging(extraHeaders) { $1 }

        let delegate = SafeSessionDelegate(maxBytes: maxBytes, maxRedirects: maxRedirects)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        var request = URLRequest(url: url)
        request.httpMethod = method.uppercased()
        request.timeoutInterval = timeout
        request.httpBody = body
        for (key, value) in extraHeaders { request.setValue(value, forHTTPHeaderField: key) }
        if body != nil, request.value(forHTTPHeaderField: "Content-Type") == nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let result: (Data, Bool, URLResponse)
        do {
            result = try await withCheckedThrowingContinuation { continuation in
                delegate.attach { value in continuation.resume(with: value) }
                session.dataTask(with: request).resume()
            }
        } catch let error as SafeNetworkError {
            throw error
        } catch let error as NSError {
            if error.domain == NSURLErrorDomain, error.code == NSURLErrorTimedOut {
                throw SafeNetworkError(kind: .timeout,
                                       detail: "The destination did not respond within \(Int(timeout)) seconds.")
            }
            throw SafeNetworkError(kind: .transport, detail: error.localizedDescription)
        }

        guard let http = result.2 as? HTTPURLResponse else {
            throw SafeNetworkError(kind: .transport, detail: "The destination did not return an HTTP response.")
        }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            headers[String(describing: key).lowercased()] = String(describing: value)
        }

        return SafeHTTPResponse(
            requestedURL: urlString,
            finalURL: http.url?.absoluteString ?? urlString,
            status: http.statusCode,
            headers: headers,
            body: result.0,
            redirects: delegate.redirects,
            truncated: result.1,
            elapsedMs: Date().timeIntervalSince(started) * 1000
        )
    }
}
