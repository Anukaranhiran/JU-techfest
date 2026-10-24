const portInput = document.getElementById("port");
const tokenInput = document.getElementById("token");
const statusBadge = document.getElementById("status");
const statusDetail = document.getElementById("statusDetail");
const resultBox = document.getElementById("result");

function badgeClass(verdict) {
  if (!verdict) return "unverified";
  if (verdict.includes("CRITICAL") || verdict.includes("HIGH")) return "high";
  if (verdict.includes("CAUTION")) return "medium";
  if (verdict.includes("LOW")) return "low";
  return "unverified";
}

async function load() {
  const stored = await chrome.storage.local.get(["port", "token"]);
  portInput.value = stored.port || 47613;
  tokenInput.value = stored.token || "";
  await checkHealth();
}

async function checkHealth() {
  try {
    const port = Number(portInput.value) || 47613;
    const response = await fetch(`http://127.0.0.1:${port}/health`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    statusBadge.textContent = "connected";
    statusBadge.className = "badge low";
    statusDetail.textContent = `${data.app} ${data.version} on 127.0.0.1:${port}. Token ${tokenInput.value ? "saved" : "not set"}.`;
    chrome.runtime.sendMessage({ type: "heartbeat" });
  } catch (error) {
    statusBadge.textContent = "offline";
    statusBadge.className = "badge high";
    statusDetail.textContent = "ScamShield app not reachable. Launch it, then check the port in Settings.";
  }
}

document.getElementById("save").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({
    type: "setSettings",
    port: Number(portInput.value) || 47613,
    token: tokenInput.value.trim()
  });
  await checkHealth();
});

document.getElementById("scan").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;
  resultBox.innerHTML = "<p class='muted'>Scanning…</p>";
  const response = await chrome.runtime.sendMessage({ type: "scan", url: tab.url });
  if (!response || !response.ok) {
    resultBox.innerHTML = `<p class="muted">Could not scan: ${response ? response.error : "no response"}</p>`;
    return;
  }
  render(response.result, tab.url);
});

function render(result, url) {
  const verdict = result.displayVerdict || "UNVERIFIED";
  const evidence = (result.evidence || [])
    .filter(item => item.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 5)
    .map(item => `<li><span class="w">+${item.weight}</span><span><span class="t">${escapeHtml(item.title)}</span><br><span class="d">${escapeHtml(item.detail)}</span></span></li>`)
    .join("");
  resultBox.innerHTML = `
    <hr>
    <span class="badge ${badgeClass(verdict)}">${verdict}</span>
    <div class="url">${escapeHtml(url)}</div>
    <div class="score"><i style="width:${Number(result.riskScore) || 0}%"></i></div>
    <p class="muted">risk ${Number(result.riskScore) || 0}/100 · ${escapeHtml(result.confidence || "")}</p>
    ${evidence ? `<h2>Evidence</h2><ul class="evidence">${evidence}</ul>` : ""}
    ${(result.limitations || []).slice(0, 3).map(l => `<p class="d">• ${escapeHtml(l)}</p>`).join("")}
  `;
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

load();
