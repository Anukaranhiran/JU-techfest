# Safari: why there is no integration in this build

Safari does not load unpacked Chromium extensions and does not accept unsigned
`webextension` folders. Shipping a working Safari layer requires all of the following:

1. A **Safari Web Extension** target inside an Xcode project (Safari app extensions are
   bundled *inside* a macOS/iOS app and signed together with it).
2. A **development or distribution certificate** (`Apple Development` /
   `Developer ID Application`) and a provisioning profile. An ad-hoc signature — which is
   what this repository uses so it can be built without an Apple account — is not accepted
   for Safari app extensions.
3. Enabling **Develop → Allow Unsigned Extensions** in Safari for local testing (resets on
   every Safari restart) or full signing for distribution.
4. Conversion of the MV3 sources with `safari-web-extension-converter`, then fixing the
   APIs Safari does not implement identically (notably `declarativeNetRequest` rule
   behaviour and background/service-worker differences).

Because of that, this build ships **no Safari extension**, and the Protection Center
reports Safari as **Not covered**. It does not fake a Safari integration.

## What Safari coverage would and would not buy

Even with a signed extension, Safari's extension model cannot give the same guarantees as
the macOS default-handler layer:

- Link clicks that open a new browser window from another app still go through
  LaunchServices first — that path is already covered by ScamShield's handler.
- A Safari extension can warn on navigation and block resources, but it cannot make the
  navigation itself "not have happened"; Safari has already started it.
- In-app webviews remain invisible regardless of browser.

## Turning this on later

The Chromium extension in `extensions/chrome` is written in MV3 and is a reasonable
starting point. To attempt Safari support:

```bash
xcrun safari-web-extension-converter extensions/chrome --project-location build/safari
open build/safari/*.xcodeproj      # set your team, run the app once
# Safari → Develop → Allow Unsigned Extensions (for local testing)
```

Then update `ProtectionEvaluator` in `Sources/ScamShield/Protection.swift` so the Safari
route is computed from a real heartbeat instead of a hardcoded `uncovered`. Until that
exists, the app must keep reporting it as uncovered.
