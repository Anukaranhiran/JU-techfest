let targetURL = "";

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function badgeClass(verdict) {
  if (!verdict) return "unverified";
  if (verdict.includes("CRITICAL") || verdict.includes("HIGH")) return "high";
  if (verdict.includes("CAUTION")) return "medium";
  if (verdict.includes("LOW")) return "low";
  return "unverified";
}

async function load() {
  const response = await chrome.runtime.sendMessage({ type: "getContext" });
  const result = response && response.result;
  targetURL = (response && response.url) || "";

  if (!targetURL) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    targetURL = tab && tab.url ? tab.url : "";
  }

  document.getElementById("url").textContent = targetURL || "(unknown destination)";

  if (!result) {
    document.getElementById("badge").textContent = "UNVERIFIED";
    document.getElementById("badge").className = "badge unverified";
    document.getElementById("headline").textContent = "This page was held, but the scan is missing";
    document.getElementById("subline").textContent =
      "The ScamShield app did not return a verdict for this navigation, so it is not being called safe.";
    return;
  }

  const verdict = result.displayVerdict || "UNVERIFIED";
  document.getElementById("badge").textContent = verdict;
  document.getElementById("badge").className = `badge ${badgeClass(verdict)}`;
  document.getElementById("headline").textContent =
    result.status === "failed" ? "ScamShield could not verify this page" : "ScamShield stopped this page";
  document.getElementById("subline").textContent =
    result.status === "failed"
      ? "The local scanner did not complete, so the destination is unverified — not safe."
      : `Checked locally in ${Math.round(result.durationMs || 0)} ms. The destination is held until you decide.`;

  const score = Number(result.riskScore) || 0;
  document.getElementById("score").textContent = `risk ${score}/100 · ${result.confidence || ""}`;
  document.getElementById("scorebar").style.width = `${Math.max(2, score)}%`;

  const evidence = (result.evidence || [])
    .filter(item => item.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 6);

  if (evidence.length) {
    document.getElementById("evidence").innerHTML = `
      <h2>Evidence</h2>
      <ul class="evidence">
        ${evidence.map(item => `
          <li>
            <span class="w">+${item.weight}</span>
            <span><span class="t">${escapeHtml(item.title)}</span><br><span class="d">${escapeHtml(item.detail)}</span></span>
          </li>`).join("")}
      </ul>`;
  }

  const limitations = (result.limitations || []).slice(0, 3);
  if (limitations.length) {
    document.getElementById("limitations").innerHTML = `
      <h2>What was not checked</h2>
      ${limitations.map(item => `<p class="d">• ${escapeHtml(item)}</p>`).join("")}`;
  }
}

document.getElementById("closed").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "keepClosed" });
});

document.getElementById("open").addEventListener("click", async () => {
  if (!targetURL) return;
  await chrome.runtime.sendMessage({ type: "openAnyway", url: targetURL });
  window.location.href = targetURL;
});

load();
