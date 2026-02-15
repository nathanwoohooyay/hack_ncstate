const API_BASE = "http://209.222.12.247:8000";
const MAX_LIMIT = 50;

const elList = document.getElementById("list");
const elStatus = document.getElementById("status");
const elRefresh = document.getElementById("refresh");

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
    return new Date(iso).toLocaleString();
  } catch {
    return iso || "";
  }
}

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status}: ${txt || resp.statusText}`);
  }
  return await resp.json();
}

function renderEmpty(msg) {
  elList.innerHTML =
    `<div class="card"><div class="meta">${escapeHTML(msg)}</div></div>`;
}

function renderReports(reports) {
  if (!Array.isArray(reports) || reports.length === 0) {
    renderEmpty("No reports yet.");
    return;
  }

  elList.innerHTML = reports.map(r => {
    const types = (r.detected_types || []).join(", ");
    const evid = r.evidence_snippets || [];

    return `
      <div class="card">
        <div class="cardTop">
          <div>
            <div class="file">${escapeHTML(r.filename || "(no filename)")}</div>
            <div class="meta">
              ${escapeHTML(formatTime(r.created_at))}<br/>
              ${escapeHTML(r.page_url || "")}
            </div>
          </div>

          <div class="badge ${badgeClass(r.risk_level)}">
            ${escapeHTML(r.risk_level.toUpperCase())} • ${escapeHTML(r.risk_score)}
          </div>
        </div>

        <div class="meta">
          <b>Detected:</b> ${escapeHTML(types || "None")}
        </div>

        <div class="details">
          <div class="meta"><b>Proof hash:</b> ${escapeHTML(r.proof_hash)}</div>
          <div class="meta"><b>Source IP:</b> ${escapeHTML(r.source_ip || "")}</div>

          ${evid.length
            ? evid.map(e => `<div class="code">${escapeHTML(e)}</div>`).join("")
            : `<div class="meta">None</div>`
          }
        </div>
      </div>
    `;
  }).join("");

  document.querySelectorAll(".card").forEach(card => {
    card.onclick = () => card.classList.toggle("open");
  });
}

async function loadReports() {
  elStatus.textContent = "Loading...";
  elList.innerHTML = "";

  try {
    const reports = await fetchJSON(
      `${API_BASE}/reports/latest?limit=${MAX_LIMIT}`
    );

    elStatus.textContent =
      `Loaded ${reports.length} report(s).`;

    renderReports(reports);

  } catch (e) {
    elStatus.textContent = `Error: ${e.message}`;
    renderEmpty("Could not connect to backend.");
  }
}

elRefresh.onclick = loadReports;

loadReports();