import Foundation
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import Vision

// MARK: - Media helpers

public enum MediaAnalyzer {

    public static let ocrLimitations = [
        "OCR reads text from the image; it does not detect cloned logos, layout mimicry or image forensics.",
        "Stylised, low-contrast, rotated or partly covered text may be missed entirely.",
        "ScamShield does not upload images anywhere — recognition runs on this Mac.",
    ]

    public static func cgImage(from data: Data) -> CGImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }

    /// Renders a QR code for a string (used by the evaluation lab and tests).
    public static func generateQRCode(_ text: String, scale: CGFloat = 12) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext()
        return context.createCGImage(scaled, from: scaled.extent)
    }

    public struct BarcodeResult: Sendable {
        public var payloads: [String]
        public var symbologies: [String]
        public var error: String?
    }

    public static func decodeBarcodes(from data: Data) -> BarcodeResult {
        guard let image = cgImage(from: data) else {
            return BarcodeResult(payloads: [], symbologies: [], error: "The file is not a readable image.")
        }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr, .aztec, .dataMatrix, .pdf417, .code128, .ean13, .ean8, .code39, .upce, .itf14]
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return BarcodeResult(payloads: [], symbologies: [], error: "Vision could not read the image: \(error.localizedDescription)")
        }
        let observations = request.results ?? []
        var payloads: [String] = []
        var symbologies: [String] = []
        for observation in observations {
            if let payload = observation.payloadStringValue, !payload.isEmpty, !payloads.contains(payload) {
                payloads.append(payload)
                symbologies.append(observation.symbology.rawValue)
            }
        }
        return BarcodeResult(payloads: payloads, symbologies: symbologies, error: nil)
    }

    public struct OCRResult: Sendable {
        public var text: String
        public var confidence: Double
        public var error: String?
    }

    public static func recognizeText(from data: Data) -> OCRResult {
        guard let image = cgImage(from: data) else {
            return OCRResult(text: "", confidence: 0, error: "The file is not a readable image.")
        }
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = true
        request.recognitionLanguages = ["en-US", "en-GB"]
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return OCRResult(text: "", confidence: 0, error: "Vision could not read the image: \(error.localizedDescription)")
        }
        let observations = request.results ?? []
        var lines: [String] = []
        var total: Float = 0
        for observation in observations {
            if let candidate = observation.topCandidates(1).first {
                lines.append(candidate.string)
                total += candidate.confidence
            }
        }
        let average = observations.isEmpty ? 0 : Double(total) / Double(observations.count)
        return OCRResult(text: lines.joined(separator: "\n"), confidence: average, error: nil)
    }
}

// MARK: - Scanner integration

public extension ScanEngine {

    /// QR images: decode the payload, then run the normal URL/message engine on it.
    func scanQRImage(_ data: Data) -> ScanResult {
        let started = Date()
        let decoded = MediaAnalyzer.decodeBarcodes(from: data)
        if let error = decoded.error {
            return failedResult(kind: .qr, input: "<image \(data.count) bytes>", reason: error, started: started)
        }
        guard let payload = decoded.payloads.first else {
            return failedResult(kind: .qr, input: "<image \(data.count) bytes>",
                                reason: "No QR or barcode was found in this image. Nothing was verified.",
                                started: started)
        }

        let looksLikeURL = payload.lowercased().hasPrefix("http://") || payload.lowercased().hasPrefix("https://")
        var base = looksLikeURL ? scanURL(payload) : scanMessage(payload)

        // Recast the result as a QR scan while keeping the underlying analysis.
        base.kind = .qr
        base.input = "QR payload: \(payload.prefix(500))"
        base.limitations.insert("Decoded \(decoded.symbologies.first ?? "barcode") payload: “\(payload.prefix(160))”.", at: 0)
        base.limitations.insert("A QR code can hide its destination; the printed image proves nothing about who made it.", at: 1)
        if !looksLikeURL {
            base.limitations.insert("The QR payload is not a web link, so it was analysed as message text.", at: 0)
        }
        base.skippedChecks.append("Visual/physical tampering checks on the code image")
        base.durationMs = Date().timeIntervalSince(started) * 1000
        return base
    }

    /// Screenshots: OCR the text, then analyse the text and every link in it.
    func scanScreenshot(_ data: Data) -> ScanResult {
        let started = Date()
        let ocr = MediaAnalyzer.recognizeText(from: data)
        if let error = ocr.error {
            return failedResult(kind: .screenshot, input: "<image \(data.count) bytes>", reason: error, started: started)
        }
        let text = ocr.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count >= 3 else {
            return failedResult(kind: .screenshot, input: "<image \(data.count) bytes>",
                                reason: "OCR found no readable text in the screenshot. Nothing was verified.",
                                started: started)
        }

        var base = scanMessage(text)
        base.kind = .screenshot
        base.input = "Screenshot OCR (\(text.count) chars): \(text.prefix(400))"
        base.limitations.insert("Text recognised locally with average OCR confidence \(String(format: "%.0f%%", ocr.confidence * 100)).", at: 0)
        base.limitations.append(contentsOf: MediaAnalyzer.ocrLimitations.prefix(2))
        base.skippedChecks.append("Logo/pixel forensics")
        if ocr.confidence < 0.4 {
            base.limitations.insert("OCR confidence is low, so the extracted text may be incomplete — treat the verdict as a partial check.", at: 0)
            base.confidence = .low
        }
        base.durationMs = Date().timeIntervalSince(started) * 1000
        return base
    }
}
