# Third-party notices

ScamShield contains original code plus algorithms adapted from the following
MIT-licensed open-source project. No third-party project is bundled as a runtime
dependency, and no third-party names or logos appear in the ScamShield interface.

## PhishLens

- Repository: https://github.com/Georgefifth/phishlens
- Source reviewed: `engine.js`, commit `b85f7c6` (2026-09-20)
- Licence: MIT
- Used for: Shannon-entropy and machine-generated hostname heuristics, fake
  public-suffix labels in subdomains, digit/hex-stuffed and consonant-only labels,
  opaque base64-like path blobs, hidden-iframe detection, high-value input-field
  detection, and same-site versus cross-site form-destination comparison.
- Adaptation: the algorithms were reimplemented in Swift in
  `Sources/ScamShieldCore/DeceptiveStructure.swift` and
  `Sources/ScamShieldCore/PageInspector.swift`, with lower weights where the original
  would double-count ScamShield's existing checks. PhishLens's brand database and
  user-interface code were not copied; ScamShield already has its own brand registry.

### MIT licence text

```
MIT License

Copyright (c) 2026 PhishLens contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Projects reviewed but not copied

- **PhishShield** (https://github.com/SiranjeeviE/PhishShield, commit `69dc24c`):
  no `LICENSE` file was present, while the README claimed MIT. Its detection also
  relied on hardcoded phishing patterns and a broad trusted-domain allowlist. No code
  was copied.
- **URL Reputation Checker** (https://github.com/newuni/url-reputation, commit
  `be8e165`): MIT. Its provider aggregation, retry/caching and Python plumbing were
  reviewed but not copied, because ScamShield already has provider-specific error
  states and an evidence-based merger. Its explainable provider-weights concept was
  already reflected in ScamShield's per-signal evidence.
