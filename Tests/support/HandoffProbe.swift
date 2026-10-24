import AppKit

// A minimal "browser" used only by integration tests. It records the exact URL that
// macOS hands it, which is how the test proves ScamShield delivered the intended
// destination to a browser rather than merely claiming to.

func append(_ line: String) {
    let path = ProcessInfo.processInfo.environment["HANDOFF_PROBE_LOG"] ?? "/tmp/scamshield-handoff.log"
    let entry = "[\(Date().timeIntervalSince1970)] \(line)\n"
    guard let data = entry.data(using: .utf8) else { return }
    if let handle = FileHandle(forWritingAtPath: path) {
        handle.seekToEndOfFile()
        handle.write(data)
        try? handle.close()
    } else {
        try? data.write(to: URL(fileURLWithPath: path))
    }
}

final class ProbeDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        append("launched argv=\(CommandLine.arguments.dropFirst())")
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        append("open=\(urls.map(\.absoluteString).joined(separator: " "))")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { NSApp.terminate(nil) }
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        append("files=\(filenames.joined(separator: " "))")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { NSApp.terminate(nil) }
    }
}

let app = NSApplication.shared
let delegate = ProbeDelegate()
app.delegate = delegate
app.setActivationPolicy(.prohibited)
app.run()
