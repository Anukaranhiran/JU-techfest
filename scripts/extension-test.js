#!/usr/bin/env node
/* Real end-to-end test for the browser extension.
 *
 * Loads extensions/chrome into an isolated Chromium profile (Chrome for Testing from the
 * local Playwright cache), points it at the running ScamShield app, and checks that:
 *   1. a benign localhost page is NOT blocked,
 *   2. a known-hostile URL is replaced by the extension's block page before it loads,
 *   3. the blocked host is remembered as a declarativeNetRequest redirect rule,
 *   4. the app received the extension heartbeat.
 *
 * Requires: the ScamShield app running (./scripts/run.sh) and playwright-core installed.
 * Usage: node scripts/extension-test.js
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const EXT = path.join(ROOT, "extensions", "chrome");
const DATA = path.join(os.homedir(), "Library", "Application Support", "ScamShield");
const PORT = Number(process.env.SCAMSHIELD_PORT || 47613);
const HOSTILE = "https://appleid-apple.com-verify-account.tk/login/confirm";

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const cache = path.join(os.homedir(), "Library", "Caches", "ms-playwright");
  if (fs.existsSync(cache)) {
    for (const entry of fs.readdirSync(cache).filter((d) => d.startsWith("chromium-")).sort().reverse()) {
      const candidate = path.join(cache, entry, "chrome-mac-arm64",
        "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing");
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  for (const candidate of ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                           "/Applications/Opera GX.app/Contents/MacOS/Opera"]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error("No Chromium binary found. Set CHROME_PATH.");
}

let failures = 0;
function check(name, passed, detail = "") {
  console.log(`${passed ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!passed) failures += 1;
}

(async () => {
  const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright-core");
  const token = fs.readFileSync(path.join(DATA, "api-token"), "utf8").trim();

  // A local benign site: proves the extension does not block ordinary pages, with no
  // dependency on internet access.
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body><h1>Local benign page</h1></body></html>");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const benign = `http://127.0.0.1:${server.address().port}/`;

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "shield-ext-"));
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: findChrome(),
    headless: true,
    args: [
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      "--no-first-run",
      "--no-default-browser-check"
    ]
  });

  try {
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 20000 });
    check("extension service worker loaded", Boolean(worker));

    await worker.evaluate(async ({ token, port }) => {
      await chrome.storage.local.set({ token, port, bypass: {} });
    }, { token, port: PORT });

    // The worker must reach the app; this is the same call the popup makes.
    const probe = await worker.evaluate(async () => {
      const stored = await chrome.storage.local.get(["token", "port"]);
      const response = await fetch(`http://127.0.0.1:${stored.port}/health`, {
        headers: { "X-ScamShield-Token": stored.token }
      });
      return { status: response.status, body: await response.text() };
    });
    check("extension reached the local scanner", probe.status === 200, probe.body.slice(0, 60));

    // 1. Benign page must load untouched.
    const page = await context.newPage();
    await page.goto(benign, { waitUntil: "domcontentloaded", timeout: 20000 });
    await page.waitForTimeout(1500);
    check("benign page not blocked", page.url().startsWith(benign), page.url());

    // 2. Hostile page must be replaced with the extension's block page.
    //    The destination does not resolve, so the navigation is aborted by the extension's
    //    redirect; the authoritative check is the tab URL the extension itself controls.
    await page.goto(HOSTILE, { timeout: 15000 }).catch(() => {});
    let blockedURL = "";
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const tabs = await worker.evaluate(() => chrome.tabs.query({}).then((list) => list.map((t) => t.url)));
      blockedURL = tabs.find((url) => url && url.includes("block.html")) || "";
      if (blockedURL) break;
      await page.waitForTimeout(250);
    }
    const isBlocked = blockedURL.includes("block.html");
    check("hostile navigation intercepted", isBlocked, blockedURL || `still at ${page.url()}`);

    if (isBlocked) {
      // Read the rendered warning from whichever page object holds the block tab.
      const blockPage = context.pages().find((p) => p.url().includes("block.html")) || page;
      const text = await blockPage.textContent("body").catch(() => "");
      check("block page shows the verdict", /CRITICAL|HIGH/.test(text || ""), (text || "").replace(/\s+/g, " ").slice(0, 80));
      check("block page names the destination", (text || "").includes("appleid-apple.com-verify-account.tk"));
    }

    // 3. The host is remembered as a real declarativeNetRequest redirect.
    const rules = await worker.evaluate(async () => {
      const stored = await chrome.storage.local.get("blockedHosts");
      const dynamic = await chrome.declarativeNetRequest.getDynamicRules();
      return { hosts: Object.keys(stored.blockedHosts || {}), rules: dynamic.length };
    });
    check("blocked host persisted", rules.hosts.includes("appleid-apple.com-verify-account.tk"), JSON.stringify(rules.hosts));
    check("declarativeNetRequest rule registered", rules.rules >= 1, `${rules.rules} rule(s)`);

    // 3b. A second visit is stopped by the declarativeNetRequest rule, i.e. before the
    //     page loads, without waiting for a fresh scan.
    const second = await context.newPage();
    await second.goto(HOSTILE, { timeout: 15000 }).catch(() => {});
    let secondURL = "";
    for (let attempt = 0; attempt < 20; attempt += 1) {
      secondURL = second.url();
      if (secondURL.includes("block.html")) break;
      await second.waitForTimeout(250);
    }
    check("repeat visit blocked before load (DNR rule)", secondURL.includes("block.html"), secondURL);
    await second.close().catch(() => {});

    // 4. The app must have recorded the extension connection.
    const heartbeat = path.join(DATA, "extension-heartbeats.json");
    const hb = fs.existsSync(heartbeat) ? fs.readFileSync(heartbeat, "utf8") : "";
    check("app recorded the extension heartbeat", hb.includes("Chrome"), hb.replace(/\s+/g, " ").slice(0, 90));
  } finally {
    await context.close().catch(() => {});
    server.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }

  console.log(failures === 0 ? "EXTENSION TEST: PASS" : `EXTENSION TEST: FAIL (${failures} failures)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((error) => {
  console.error(`EXTENSION TEST: ERROR — ${error.message}`);
  if (error.message.includes("Cannot find module")) {
    console.error("Install the test dependency first: npm i --no-save playwright-core");
  }
  process.exit(1);
});
