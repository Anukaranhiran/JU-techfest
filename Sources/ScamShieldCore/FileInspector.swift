import CryptoKit
import Foundation

// MARK: - Local file inspection
//
// Files are read as bytes and never executed or uploaded. The only outbound request
// is an optional VirusTotal *hash* lookup, which reveals the SHA-256, not the file.

public struct FileInspection: Sendable {
    public var fileName: String
    public var fileSize: Int
    public var sha256: String
    public var md5: String
    public var detectedType: String?
    public var extensionName: String
    public var extensionMismatch: Bool
    public var evidence: [Evidence]
    public var checks: [CheckRecord]
    public var limitations: [String]
    public var providerOutcomes: [ProviderOutcome]
}

public enum FileInspector {

    struct Signature {
        let name: String
        let bytes: [UInt8]
        let offset: Int
        let dangerous: Bool
    }

    static let signatures: [Signature] = [
        Signature(name: "Windows executable (MZ/PE)", bytes: [0x4D, 0x5A], offset: 0, dangerous: true),
        Signature(name: "ZIP archive (also APK/JAR/DOCX)", bytes: [0x50, 0x4B, 0x03, 0x04], offset: 0, dangerous: true),
        Signature(name: "RAR archive", bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], offset: 0, dangerous: true),
        Signature(name: "7-Zip archive", bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], offset: 0, dangerous: true),
        Signature(name: "Mach-O executable", bytes: [0xCF, 0xFA, 0xED, 0xFE], offset: 0, dangerous: true),
        Signature(name: "Mach-O executable (64-bit)", bytes: [0xCF, 0xFA, 0xED, 0xFE], offset: 0, dangerous: true),
        Signature(name: "Mach-O universal binary", bytes: [0xCA, 0xFE, 0xBA, 0xBE], offset: 0, dangerous: true),
        Signature(name: "ELF executable", bytes: [0x7F, 0x45, 0x4C, 0x46], offset: 0, dangerous: true),
        Signature(name: "PDF document", bytes: [0x25, 0x50, 0x44, 0x46], offset: 0, dangerous: false),
        Signature(name: "OLE document (legacy Office)", bytes: [0xD0, 0xCF, 0x11, 0xE0], offset: 0, dangerous: false),
        Signature(name: "Disk image (DMG)", bytes: Array("koly".utf8), offset: 0, dangerous: true),
        Signature(name: "PNG image", bytes: [0x89, 0x50, 0x4E, 0x47], offset: 0, dangerous: false),
        Signature(name: "JPEG image", bytes: [0xFF, 0xD8, 0xFF], offset: 0, dangerous: false),
        Signature(name: "GIF image", bytes: Array("GIF8".utf8), offset: 0, dangerous: false),
        Signature(name: "HTML document", bytes: Array("<!DOCTYPE".utf8), offset: 0, dangerous: false),
        Signature(name: "RTF document", bytes: Array("{\\rtf".utf8), offset: 0, dangerous: false),
    ]

    static let dangerousExtensions: Set<String> = [
        "exe", "msi", "apk", "dmg", "pkg", "scr", "vbs", "bat", "cmd", "jar", "ps1",
        "iso", "img", "hta", "lnk", "reg", "zip", "rar", "7z", "ace", "js", "jse",
        "wsf", "wsh", "com", "pif", "cpl", "docm", "xlsm", "pptm",
    ]

    public static func sha256(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func md5(of data: Data) -> String {
        Insecure.MD5.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Reads at most 64 MB. Larger files get a hash of the first 64 MB with an
    /// explicit limitation rather than being read into memory without bound.
    public static func inspect(fileURL: URL, virusTotalKey: String) async -> FileInspection {
        let name = fileURL.lastPathComponent
        let ext = fileURL.pathExtension.lowercased()
        var evidence: [Evidence] = []
        var checks: [CheckRecord] = []
        var limitations: [String] = [
            "The file was not executed, opened in an application, or uploaded.",
            "Static signatures can be spoofed and do not prove intent.",
        ]

        let limit = 64 * 1024 * 1024
        let data: Data
        do {
            let handle = try FileHandle(forReadingFrom: fileURL)
            defer { try? handle.close() }
            data = try handle.read(upToCount: limit) ?? Data()
        } catch {
            return FileInspection(fileName: name, fileSize: 0, sha256: "", md5: "", detectedType: nil,
                                  extensionName: ext, extensionMismatch: false, evidence: [],
                                  checks: [CheckRecord(name: "Read file", state: .failed, detail: error.localizedDescription)],
                                  limitations: ["The file could not be read: \(error.localizedDescription)"],
                                  providerOutcomes: [])
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int) ?? data.count
        if size > limit {
            limitations.append("Only the first 64 MB were hashed; the file is \(size / 1_048_576) MB.")
        }

        let hash = sha256(of: data)
        let md5Hash = md5(of: data)
        checks.append(CheckRecord(name: "SHA-256", state: .passed, detail: hash))
        checks.append(CheckRecord(name: "Read bytes", state: .passed, detail: "\(data.count) byte(s) read."))

        var detected: String?
        var detectedDangerous = false
        for signature in signatures where data.count >= signature.offset + signature.bytes.count {
            let slice = [UInt8](data[signature.offset..<(signature.offset + signature.bytes.count)])
            if slice == signature.bytes {
                detected = signature.name
                detectedDangerous = signature.dangerous
                break
            }
        }
        checks.append(CheckRecord(name: "File signature", state: detected == nil ? .unavailable : .passed,
                                  detail: detected ?? "No known signature at the start of the file."))

        // Type/extension mismatch.
        let expectedForExtension: [String: String] = [
            "exe": "Windows", "dll": "Windows", "msi": "OLE", "pdf": "PDF", "zip": "ZIP",
            "docx": "ZIP", "xlsx": "ZIP", "pptx": "ZIP", "apk": "ZIP", "jar": "ZIP",
            "png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "gif": "GIF", "dmg": "Disk image",
            "iso": "ISO", "rtf": "RTF",
        ]
        var mismatch = false
        if let detected, let expected = expectedForExtension[ext], !detected.contains(expected) {
            mismatch = true
            evidence.append(Evidence(code: "file.extension-mismatch", title: "Extension does not match content",
                detail: "The file is named .\(ext) but its bytes look like \(detected). Double extensions and mismatches are used to disguise executables.",
                weight: 26, category: .content))
        }

        if dangerousExtensions.contains(ext) {
            evidence.append(Evidence(code: "file.dangerous-extension", title: "Executable or archive extension (.\(ext))",
                detail: "ScamShield never executes files. Treat .\(ext) attachments from messages as hostile unless you independently expected this exact file.",
                weight: 24, category: .content))
        }
        if detectedDangerous && !dangerousExtensions.contains(ext) {
            evidence.append(Evidence(code: "file.dangerous-signature", title: "Executable content under a different name",
                detail: "The bytes are \(detected ?? "an executable"), but the name suggests otherwise. That is a deliberate disguise technique.",
                weight: 32, category: .content))
        }
        if data.isEmpty {
            evidence.append(Evidence(code: "file.empty", title: "Empty file",
                detail: "The file contains no data. It cannot be assessed.",
                weight: 4, category: .content))
        }

        var outcomes: [ProviderOutcome] = []
        if !virusTotalKey.trimmingCharacters(in: .whitespaces).isEmpty {
            do {
                let response = try await SafeFetcher.fetch("https://www.virustotal.com/api/v3/files/\(hash)",
                    timeout: 10, maxBytes: 256 * 1024, extraHeaders: ["x-apikey": virusTotalKey])
                if response.status == 200,
                   let root = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
                   let dataObject = root["data"] as? [String: Any],
                   let attributes = dataObject["attributes"] as? [String: Any],
                   let stats = attributes["last_analysis_stats"] as? [String: Any] {
                    let malicious = stats["malicious"] as? Int ?? 0
                    let suspicious = stats["suspicious"] as? Int ?? 0
                    let total = ["malicious", "suspicious", "harmless", "undetected"].reduce(0) { $0 + (stats[$1] as? Int ?? 0) }
                    if malicious > 0 {
                        outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .malicious,
                                                        detail: "\(malicious) of \(total) engines flagged this SHA-256."))
                        evidence.append(Evidence(code: "file.reputation-malicious", title: "File hash flagged by VirusTotal",
                            detail: "\(malicious) of \(total) engines flagged this exact file hash.", weight: 85, category: .reputation))
                    } else if suspicious > 0 {
                        outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .suspicious,
                                                        detail: "\(suspicious) of \(total) engines marked this hash suspicious."))
                        evidence.append(Evidence(code: "file.reputation-suspicious", title: "File hash marked suspicious",
                            detail: "\(suspicious) of \(total) engines marked this hash suspicious.", weight: 45, category: .reputation))
                    } else {
                        outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .clean,
                                                        detail: "No engine flagged this hash. Not a guarantee."))
                    }
                    checks.append(CheckRecord(name: "VirusTotal hash lookup", state: .passed, detail: "HTTP 200."))
                } else if response.status == 404 {
                    outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .unknown,
                                                    detail: "VirusTotal has never seen this hash. Unknown is not clean."))
                    checks.append(CheckRecord(name: "VirusTotal hash lookup", state: .passed, detail: "HTTP 404: no record."))
                } else {
                    outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .error,
                                                    detail: "VirusTotal returned HTTP \(response.status)."))
                    checks.append(CheckRecord(name: "VirusTotal hash lookup", state: .failed, detail: "HTTP \(response.status)."))
                }
            } catch {
                outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .error,
                                                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
                checks.append(CheckRecord(name: "VirusTotal hash lookup", state: .failed, detail: error.localizedDescription))
            }
        } else {
            outcomes.append(ProviderOutcome(provider: "VirusTotal", status: .notConfigured,
                                            detail: "No VirusTotal API key. Only local signatures and hashes ran."))
            checks.append(CheckRecord(name: "VirusTotal hash lookup", state: .skipped, detail: "No API key configured."))
        }
        limitations.append("Only the file hash is sent to VirusTotal, and only when a key is configured. The file itself never leaves this Mac.")

        return FileInspection(fileName: name, fileSize: size, sha256: hash, md5: md5Hash,
                              detectedType: detected, extensionName: ext, extensionMismatch: mismatch,
                              evidence: evidence, checks: checks, limitations: limitations,
                              providerOutcomes: outcomes)
    }
}
