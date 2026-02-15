const DEFAULT_API_BASE = "http://209.222.12.247:8000";
const MAX_LIMIT = 50;

const elList = document.getElementById("list");
const elStatus = document.getElementById("status");
const elRefresh = document.getElementById("refresh");
const elApiBase = document.getElementById("apiBase");
const elSaveApi = document.getElementById("saveApi");

function escapeHTML(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function badgeClass(level) {
  if (level === "high") return "high";
  if (level === "medium") return "medium";
  return "low";
}

function formatTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso || "";
  }
}

async function getApiBase() {
  const stored = await chrome.storage.local.get(["apiBase"]);
  return stored.apiBase || DEFAULT_API_BASE;
}

async function setApiBase(val) {
  await chrome.storage.local.set({ apiBase: val });
}

async function fetchJSON(url) {
  const resp = await fetch(url, { method: "GET" });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status}: ${txt || resp.statusText}`);
  }
  return await resp.json();
}

function renderEmpty(msg) {
  elList.innerHTML = `<div class="card"><div class="meta">${escapeHTML(msg)}</div></div>`;
}

function renderReports(reports) {
  if (!Array.isArray(reports) || reports.length === 0) {
    renderEmpty("No reports yet. Upload a file and scan to create one.");
    return;
  }

  elList.innerHTML = reports.map((r) => {
    const types = Array.isArray(r.detected_types) ? r.detected_types.join(", ") : "";
    const evid = Array.isArray(r.evidence_snippets) ? r.evidence_snippets : [];
    const risk = Number(r.risk_score ?? 0);
    const level = String(r.risk_level || "low");

    return `
      <div class="card" data-id="${escapeHTML(r.id)}">
        <div class="cardTop">
          <div>
            <div class="file">${escapeHTML(r.filename || "(no filename)")}</div>
            <div class="meta">
              ${escapeHTML(formatTime(r.created_at))}<br/>
              ${escapeHTML(r.page_url || "")}
            </div>
          </div>
          <div class="badge ${badgeClass(level)}">${escapeHTML(level.toUpperCase())} • ${escapeHTML(risk)}</div>
        </div>

        <div class="meta" style="margin-top:8px;">
          <b>Detected:</b> ${escapeHTML(types || "None")}
        </div>

        <div class="details">
          <div class="meta"><b>Proof hash:</b> ${escapeHTML(r.proof_hash || "")}</div>
          <div class="meta"><b>Source IP:</b> ${escapeHTML(r.source_ip || "")}</div>
          <div class="meta"><b>Evidence:</b></div>
          ${evid.length ? evid.slice(0, 8).map(s => `<div class="code">${escapeHTML(s)}</div>`).join("") : `<div class="meta">None</div>`}
        </div>
      </div>
    `;
  }).join("");

  // click-to-expand
  for (const card of elList.querySelectorAll(".card")) {
    card.addEventListener("click", () => {
      card.classList.toggle("open");
    });
  }
}

async function loadReports() {
  elStatus.textContent = "Loading…";
  elList.innerHTML = "";

  try {
    const apiBase = await getApiBase();
    const url = `${apiBase.replace(/\/$/, "")}/reports/latest?limit=${MAX_LIMIT}`;
    const reports = await fetchJSON(url);
    elStatus.textContent = `Loaded ${Array.isArray(reports) ? reports.length : 0} report(s). Click a card to expand.`;
    renderReports(reports);
  } catch (e) {
    elStatus.textContent = `Error: ${e.message || e}`;
    renderEmpty("Could not load reports. Check API base + server connectivity.");
  }
}

async function init() {
  const apiBase = await getApiBase();
  elApiBase.value = apiBase;

  elSaveApi.addEventListener("click", async () => {
    const val = elApiBase.value.trim();
    if (!val.startsWith("http://") && !val.startsWith("https://")) {
      elStatus.textContent = "API base must start with http:// or https://";
      return;
    }
    await setApiBase(val.replace(/\/$/, ""));
    elStatus.textContent = "Saved API base.";
    await loadReports();
  });

  elRefresh.addEventListener("click", loadReports);

  await loadReports();
}

init();