# macOS middle-layer feasibility (measured, not assumed)

Machine: macOS 27.0.1 as reported by `sw_vers`, Apple Silicon, Swift 6.4, Xcode 26 toolchain.
Everything below was executed on this Mac before the product was built.

## Experiments and results

### 1. Can a locally built, ad-hoc signed app receive system link opens?

Probe bundle `com.scamshield.probe` declared `http`/`https` in `CFBundleURLTypes`, was signed with `codesign --sign -`, registered with `lsregister -f`, then:

```
open -a probe/dist/ProbeHandler.app "https://example.com/a?b=1"
→ openURLs=["https://example.com/a?b=1"]
```

**Result: yes.** No admin rights, no Developer ID, no notarisation. The URL arrives through `application(_:open:)` with the query intact.

### 2. Can that bundle become the system default web handler?

Several approaches were tried, and only one worked:

| Approach | Result |
|---|---|
| `LSSetDefaultHandlerForURLScheme("https", bundleID)` from a plain CLI process | OSStatus `0`, **but the handler never changed** — silently ignored |
| `LSSetDefaultRoleHandlerForContentType("com.apple.default-app.web-browser", …)` | OSStatus `-50` (paramErr) |
| `NSWorkspace.setDefaultApplication(at:…)` from a plain CLI process, completion waited on with a semaphore | Callback never ran (semaphore blocked the main run loop), so the apparent "ok" was meaningless |
| `NSWorkspace.setDefaultApplication` **from inside the app bundle**, async, verified afterwards | **Worked**: `http -> com.scamshield.probe`, `https -> com.scamshield.probe` |

Two bundle properties were changed together just before this succeeded, so their individual necessity was not isolated:

- the bundle stopped being `LSUIElement` (a regular app is what LaunchServices treats as a browser candidate),
- it claimed `com.apple.default-app.web-browser` in `CFBundleDocumentTypes`.

macOS also lists an app as a "Default web browser" candidate only when it claims that UTI; browsers such as Chrome declare `public.html` and are signed, but the launch-services dump for this probe showed no claims at all until the UTI was added.

### 3. Does a plain `open` go through the handler?

With the probe as the default handler:

```
open "https://suspicious-test.example/verify-account?id=99"
→ openURLs=["https://suspicious-test.example/verify-account?id=99"]
```

**Result: yes.** `open` uses LaunchServices, which is the same path apps such as Mail, WhatsApp, Slack and Discord use for external links. Nothing was navigated in a browser.

### 4. Can an approved URL be handed to a specific browser without looping?

```
NSWorkspace.open([url], withApplicationAt: browserURL, configuration: …)
```

With the probe app as handler and the stub browser as target, the stub logged the exact URL. Because the target application is named explicitly, the system default handler is not consulted, so there is no loop. The app additionally ignores a duplicate delivery of the same URL within 3 seconds and refuses to target itself.

### 5. Can an app hand the default-browser role to a different app?

**No.** With ScamShield as the handler, all of these failed with `NSCocoaErrorDomain 256` ("The file couldn't be opened"), each taking ~5 s: Opera GX, Safari, Chrome, and even another bundle. `LSSetDefaultHandlerForURLScheme` returned `0` without effect, and the stored `LSHandlers` entries did not change.

This is a macOS security property: an app may claim the role **for itself**, but only the user (System Settings) may point the role at another app. Consequences implemented in the product:

- The app attempts the restore, then **opens System Settings → Desktop & Dock** and explains why it cannot do it, instead of pretending it succeeded.
- `scripts/restore-browser.sh` provides an explicit operator recovery (rewrites handler records + restarts `lsd`) and verifies the result. It was used to return this Mac to Opera GX after testing.

### 6. Conflicts observed on a shared machine

Another locally installed app (`com.scamshield.desktop`, a Tauri build outside this workspace) had claimed the handler earlier and re-asserted it at least once. This is worth knowing: the default-browser role is a single global slot, so two security tools fighting over it will each believe the other is a hijacker. ScamShield never changes the handler without a user action, and always reports the bundle ID it observes.

## Conclusion

The default-handler approach is the strongest *supported* macOS middle layer:

- genuinely before navigation for every LaunchServices link open,
- no kernel extensions, no Network Extension entitlement, no admin rights,
- reversible by the user at any time via System Settings,
- with a hard limit: apps that render links in their own webview never call LaunchServices, so no system-level product can intercept them.
