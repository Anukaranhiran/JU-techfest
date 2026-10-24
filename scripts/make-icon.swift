#!/usr/bin/env swift
import AppKit
import Foundation

// Renders AppIcon.iconset from a drawn shield, then the caller runs iconutil.

let outputDirectory = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "./build/AppIcon.iconset")
try? FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

func render(size: Int) -> Data? {
    let dimension = CGFloat(size)
    let image = NSImage(size: NSSize(width: dimension, height: dimension))
    image.lockFocus()
    guard let context = NSGraphicsContext.current?.cgContext else {
        image.unlockFocus()
        return nil
    }

    let rect = CGRect(x: 0, y: 0, width: dimension, height: dimension)
    let corner = dimension * 0.22
    let path = CGPath(roundedRect: rect.insetBy(dx: dimension * 0.04, dy: dimension * 0.04),
                      cornerWidth: corner, cornerHeight: corner, transform: nil)
    context.addPath(path)
    context.clip()
    let colors = [
        NSColor(red: 0.06, green: 0.11, blue: 0.20, alpha: 1).cgColor,
        NSColor(red: 0.10, green: 0.28, blue: 0.42, alpha: 1).cgColor,
    ] as CFArray
    if let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1]) {
        context.drawLinearGradient(gradient, start: .zero, end: CGPoint(x: dimension, y: dimension), options: [])
    }

    if let symbol = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil) {
        let configured = symbol.withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: dimension * 0.52, weight: .semibold))?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [.white]))
        if let configured {
            let symbolSize = configured.size
            let scale = min(dimension * 0.6 / max(symbolSize.width, 1), dimension * 0.6 / max(symbolSize.height, 1))
            let drawSize = NSSize(width: symbolSize.width * scale, height: symbolSize.height * scale)
            configured.draw(in: NSRect(x: (dimension - drawSize.width) / 2,
                                       y: (dimension - drawSize.height) / 2,
                                       width: drawSize.width, height: drawSize.height))
        }
    }
    image.unlockFocus()

    guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else { return nil }
    return rep.representation(using: .png, properties: [:])
}

let variants: [(String, Int)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]

for (name, size) in variants {
    guard let data = render(size: size) else {
        FileHandle.standardError.write(Data("failed to render \(name)\n".utf8))
        exit(1)
    }
    try data.write(to: outputDirectory.appendingPathComponent(name))
}
print(outputDirectory.path)
