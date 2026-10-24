/* ScamShield browser extension (Chrome / Opera GX, MV3)
 *
 * Two layers of protection, both driven by the local ScamShield app:
 *  1. declarativeNetRequest rules for destinations already known to be high risk.
 *     These redirect *before* the page loads — real pre-navigation blocking.
 *  2. webNavigation.onBeforeNavigate for never-seen URLs: ask the local scanner,
 *     and if it says high/critical, replace the tab with the warning page.
 *     Chrome has already started the navigation at that point, so the request may
 *     reach the server; this is a best-effort warning, not a guarantee.
 */

const DEFAULT_PORT = 47613;
const MAX_RULES = 200;

async function getSettings() {
  const stored = await chrome.storage.local.get(["port", "token", "bypass"]);
  return {
    port: stored.port || DEFAULT_PORT,
    token: stored.token || "",
    bypass: stored.bypass || {}
  };
}

async function api(path, body, timeoutMs = 8000) {
  const { port, token } = await getSettings();
  if (!token) throw new Error("No token configured. Open the ScamShield popup and paste the port and token.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-ScamShield-Token": token },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`ScamShield API ${response.status}`);
    return response.json();
  } finally {
    clearTimeout(timer);
  }
}

function browserName() {
  const ua = navigator.userAgent;
  if (ua.includes("OPR/")) return "Opera GX";
  if (ua.includes("Edg/")) return "Edge";
  return "Chrome";
}

async function heartbeat() {
  try {
    await api("/heartbeat", { browser: browserName(), version: chrome.runtime.getManifest().version });
  } catch (error) {
    // Silent: the app shows "no extension connected" when this fails.
  }
}

// ---------- Known-bad destinations ----------

async function blockedHosts() {
  const { blockedHosts = {} } = await chrome.storage.local.get("blockedHosts");
  return blockedHosts;
}

async function rememberBlockedHost(url, verdict) {
  const host = safeHost(url);
  if (!host) return;
  const hosts = await blockedHosts();
  hosts[host] = { verdict: verdict || "HIGH RISK", at: Date.now() };
  const keys = Object.keys(hosts);
  if (keys.length > MAX_RULES) {
    keys.sort((a, b) => hosts[a].at - hosts[b].at);
    keys.slice(0, keys.length - MAX_RULES).forEach(k => delete hosts[k]);
  }
  await chrome.storage.local.set({ blockedHosts: hosts });
  await syncRules();
}

async function forgetHost(host) {
  const hosts = await blockedHosts();
  if (hosts[host]) {
    delete hosts[host];
    await chrome.storage.local.set({ blockedHosts: hosts });
    await syncRules();
  }
}

async function syncRules() {
  const hosts = await blockedHosts();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map(r => r.id);
  const blockPage = chrome.runtime.getURL("block.html");
  const addRules = Object.keys(hosts).map((host, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: "redirect", redirect: { url: blockPage } },
    condition: {
      // Match the host and its subdomains on main-frame navigations only.
      requestDomains: [host],
      resourceTypes: ["main_frame"]
    }
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

function safeHost(value) {
  try {
    const url = new URL(value);
    return url.hostname;
  } catch {
    return null;
  }
}

// ---------- Navigation guard ----------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!/^https?:/i.test(url)) return;

  const host = safeHost(url);
  if (!host) return;

  const { bypass } = await getSettings();
  if (bypass[host] && Date.now() - bypass[host] < 10 * 60 * 1000) return;

  // Where the tab was before this navigation. If the destination is unreachable, Chromium
  // rolls the tab back to this page and we must still show the verdict.
  const priorURL = await chrome.tabs.get(details.tabId).then((tab) => tab.url).catch(() => null);

  try {
    const result = await api("/scan", { url, browser: browserName() }, 60000);
    if (result.block) {
      await rememberBlockedHost(url, result.displayVerdict || result.verdict);
      await chrome.storage.session.set({ [`context:${details.tabId}`]: { url, result } });
      const blockPage = chrome.runtime.getURL("block.html");
      await chrome.tabs.update(details.tabId, { url: blockPage }).catch(() => {});
      // If the destination turns out to be unreachable, Chromium can commit its own error
      // page a moment later and discard the redirect above. Re-apply it once so the user
      // sees the verdict instead of a bare network error — but never hijack a tab that the
      // user has navigated somewhere else in the meantime.
      setTimeout(async () => {
        try {
          const tab = await chrome.tabs.get(details.tabId);
          const settled = tab && (tab.url === url
            || tab.url.startsWith("chrome-error://")
            || (priorURL && tab.url === priorURL));
          if (settled && tab.url !== blockPage) {
            await chrome.tabs.update(details.tabId, { url: blockPage });
          }
        } catch (error) {
          // Tab closed in the meantime; nothing to protect.
        }
      }, 400);
    }
  } catch (error) {
    // Scanner unreachable or timed out: never silently pretend the page was checked,
    // and never leave the user on an unverified destination without a warning.
    const blockPage = chrome.runtime.getURL("block.html");
    await chrome.storage.session.set({
      [`context:${details.tabId}`]: {
        url,
        result: {
          status: "failed",
          displayVerdict: "UNVERIFIED",
          verdict: "UNVERIFIED",
          riskScore: 0,
          evidence: [],
          limitations: [String(error)]
        }
      }
    });
    await chrome.tabs.update(details.tabId, { url: blockPage }).catch(() => {});
  }
});

// ---------- Messages from popup / block page ----------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message.type) {
      case "heartbeat": {
        await heartbeat();
        sendResponse({ ok: true });
        break;
      }
      case "getContext": {
        const tabId = sender.tab ? sender.tab.id : message.tabId;
        const key = `context:${tabId}`;
        const stored = await chrome.storage.session.get(key);
        const context = stored[key] || null;
        if (context) {
          sendResponse(context);
        } else {
          sendResponse({ url: message.url || "", result: null });
        }
        break;
      }
      case "scan": {
        try {
          // A popup scan explicitly asks for the full live pipeline (redirects,
          // reputation and page inspection). Automatic pre-navigation checks stay
          // structural so they can answer quickly.
          const result = await api("/scan", { url: message.url, browser: browserName(), live: true }, 45000);
          sendResponse({ ok: true, result });
        } catch (error) {
          sendResponse({ ok: false, error: String(error) });
        }
        break;
      }
      case "openAnyway": {
        const host = safeHost(message.url);
        try {
          await api("/open", { url: message.url, browser: browserName() });
        } catch (error) {
          // Even if the app is unreachable, honour the user's explicit choice.
        }
        if (host) {
          const { bypass = {} } = await getSettings();
          bypass[host] = Date.now();
          await chrome.storage.local.set({ bypass });
          await forgetHost(host);
        }
        sendResponse({ ok: true });
        break;
      }
      case "keepClosed": {
        const tabId = sender.tab ? sender.tab.id : message.tabId;
        if (tabId != null) {
          try { await chrome.tabs.remove(tabId); } catch { await chrome.tabs.update(tabId, { url: "about:blank" }); }
        }
        sendResponse({ ok: true });
        break;
      }
      case "setSettings": {
        await chrome.storage.local.set({ port: message.port, token: message.token });
        await heartbeat();
        sendResponse({ ok: true });
        break;
      }
      default:
        sendResponse({ ok: false, error: "unknown message" });
    }
  })();
  return true;
});

chrome.runtime.onInstalled.addListener(async () => {
  await syncRules();
  await heartbeat();
});

chrome.runtime.onStartup.addListener(async () => {
  await syncRules();
  await heartbeat();
});

chrome.alarms.create("scamshield-heartbeat", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "scamshield-heartbeat") heartbeat();
});
