# Gemini integration: discovery, selection and verified generation

This document describes the current Gemini path in ScamShield. It replaces the
earlier assumption that one hardcoded model would always be available.

## What was wrong

The previous implementation:

- hardcoded `gemini-2.0-flash` as the Gemini model;
- had no model discovery, so it could not know what the configured key could use;
- inserted the model string directly into `/v1beta/models/{model}:generateContent`.
  A resource name copied from Google's list — `models/gemini-…` — produced
  `/models/models/…` and failed;
- collapsed every 401/403 into "invalid API key" and every other non-2xx into a
  generic HTTP message;
- accepted any nonempty text from `candidates[0]`, without checking
  `promptFeedback.blockReason`, `finishReason`, thought parts or empty parts;
- asked for `responseMimeType: application/json` on calls that only needed plain
  text (connection test and commentary);
- had no fallback when the selected model was retired or unavailable to the key.

The root cause was therefore not one bad URL. It was the absence of a real
discovery/verification step: the application assumed a model existed and had no
accurate diagnosis when Google said otherwise.

## API endpoints used

Discovery:

```
GET https://generativelanguage.googleapis.com/v1beta/models?pageSize=100
x-goog-api-key: <key>
```

Generation:

```
POST https://generativelanguage.googleapis.com/v1beta/models/{modelID}:generateContent
x-goog-api-key: <key>
Content-Type: application/json
```

The model id is taken from the discovered resource name (`models/<id>`) with the
`models/` prefix removed, validated against a safe character set, and path-encoded.
The key is sent in the header, never in the URL. Requests keep the existing
SSRF-hardened `SafeFetcher` and its timeout/response-size limits.

## Automatic discovery

`GeminiModelDiscovery`:

1. requires a nonempty key;
2. lists models visible to that key, following `nextPageToken`;
3. bounds pagination to 8 pages and each response to 512 KB;
4. decodes entries leniently, so one malformed entry does not discard the page;
5. removes duplicate ids;
6. keeps only resources whose `supportedGenerationMethods` contains
   `generateContent`;
7. excludes embedding, AQA, Imagen, Veo, TTS, audio, image, live and similar
   specialized resources;
8. ranks the remainder (newer version, stable over preview/experimental,
   Flash/Flash-Lite over Pro, deterministic id tie-break).

No model name is assumed to exist. If the list is empty or has no compatible
entries, the UI reports **No compatible models available** and no generation is
attempted.

## Automatic selection and verification

`GeminiModelSelector` probes ranked candidates, at most 6 by default:

- each probe is a tiny real `generateContent` request;
- a probe only succeeds if the response contains nonempty **visible** text (thought
  parts are ignored);
- the first successful candidate is saved with its discovery and verification
  timestamps;
- credential, permission, quota, rate-limit, timeout and network failures stop
  probing immediately;
- model-specific failures (unavailable, unsupported, empty/malformed content) move
  to the next bounded candidate.

A successful HTTP status alone is never treated as connected. Saving a key or
fetching the model list is also never shown as **Connected**.

## Caching and fallback

- Discovery metadata and the verified model id are stored in `settings.json`.
- The API key remains only in the login Keychain as a generic password.
- A SHA-256 fingerprint (not the key) invalidates a cached selection when the key
  changes.
- A key change, base-URL/provider change, or **Clear discovery** removes the cached
  model list and verification.
- Normal scans reuse the cached model; they do not probe models on every scan.
- If the cached model becomes unavailable during a scan, the client makes **one**
  discovery refresh and tries at most 2 alternative compatible models.
- If a fallback model answers, its id is adopted for subsequent scans.
- Quota-exhausted requests are not retried across models.

## Settings UI

The AI section now provides:

- Gemini API key entry (Keychain) with Save/Remove;
- **Discover & test available models**;
- **Test Gemini connection**;
- **Clear discovery**;
- progress states for discovery and per-model testing;
- the compatible-model list and optional manual selection;
- the selected/verified model and last successful test time;
- errors that distinguish invalid key, permission, quota, rate limit, network,
  model unavailable and malformed response.

Manual selection is accepted only from the current discovery result and is probed
before it can be shown as working. **Use AI analysis in live scans** stays disabled
until a Gemini model has actually been selected.

## Generation and response handling

- System instructions and user content use the documented `systemInstruction` and
  `contents` schema.
- `responseMimeType: application/json` is requested only when the caller expects
  structured JSON (scan analysis). Plain-text tasks do not request it.
- The decoder handles `promptFeedback.blockReason`, missing candidates, missing
  content, empty parts, thought-only parts, `finishReason` and malformed JSON.
- Google's structured error envelope is inspected before classifying an error.
  A 403 is not automatically an invalid key.
- Provider messages are redacted before they reach the UI, history or any error
  string.

## What the common errors mean

| UI state | Meaning |
|---|---|
| Invalid API key | Google explicitly rejected the key (`API key not valid`, 401, `UNAUTHENTICATED`, `API_KEY_INVALID`). Correct the key. |
| Permission or access denied | The key is recognized but the project/account may not use this resource (403 `PERMISSION_DENIED`). Check API enablement and project access. |
| Quota exhausted | 429 with an explicit quota/billing message. Probing stops. Check the Google AI plan and billing. |
| Rate limited | 429 without quota exhaustion. Wait and retry; probing stops. |
| Temporary network failure | Timeout or transport failure. No AI finding was added. |
| Model unavailable | The model is gone or not visible to this key. Discovery refreshes once and tries a bounded alternative. |
| No compatible models available | The key sees no text-generation model. This is not a clean result; AI did not run. |
| Invalid API response | Malformed JSON, missing candidates/parts or unusable generated content. |
| Connected | A real `generateContent` request returned nonempty visible text and that model was saved. |

## Privacy and verdict safety

Unchanged from the existing design:

- AI analysis and commentary are explicit opt-ins, off by default.
- Only bounded deterministic evidence and a short plain-text excerpt are sent;
  never raw HTML, browsing history, clipboard contents, passwords or files.
- Page text is delimited as untrusted data and common injection lead-ins are removed.
- Gemini is explanatory. Its validated findings can add corroborating evidence but
  can never erase deterministic evidence, lower a score/level, or turn a suspicious
  URL into safe.

## Automated tests

`Tests/ScamShieldCoreTests/GeminiIntegrationTests.swift` uses a controlled
`AIHTTPTransport`; no test contacts Google or needs a real key. It covers:

1. model-list decoding;
2. multi-page discovery and `x-goog-api-key` header;
3. filtering incompatible models;
4. duplicate/malformed entries;
5. successful candidate probing;
6. first candidate fails, second succeeds;
7. invalid key;
8. permission denied (not misreported as an invalid key);
9. model unavailable;
10. rate limit vs quota exhaustion; quota stops probing;
11. network timeout;
12. malformed generation response;
13. empty and safety-blocked content;
14. key change invalidating cached selection;
15. cached alternative without rediscovery, and one rediscovery fallback;
16. no compatible models;
17. secret redaction;
18. Gemini report preserving the deterministic verdict;
19. model resource-name normalization.

Verification run on this machine:

```
swift build            → Build complete
swift build -c release → Build complete
swift test             → 119 tests, 0 failures
```

Existing integration/security assertions were not weakened.

## Live verification status

A Gemini key was present in the app's Keychain. A bounded live
`discoverAndSelect(maxProbes: 3)` was attempted through the new core code without
printing the key. Google returned:

> You exceeded your current quota, please check your plan and billing details.

The client correctly classified this as **quota exhausted**, stopped probing, and
did **not** report Connected or fabricate an explanation. Because no generated text
was returned, **a successful live Gemini generation has not been verified in this
run**. Automated fixture tests pass. Live success still requires a key/project with
available Gemini quota.

Model access, quota and available families are properties of the Google Cloud
project behind the key. A successful test does not guarantee every documented model
is available to every account.
