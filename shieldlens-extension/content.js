// ShieldLens MVP - Person 1
// Upload interception + local scan + UI (ui.css) + "Scan with AI" button for binary + backend wiring
// Copy/paste this entire file into content.js

(() => {
  console.log("ShieldLens injected.");

  // ===== Backend switch =====
  const USE_BACKEND = true; // <- set to true when backend is running
  const BACKEND_URL = "http://209.222.12.247:8000"; // <- change to Vultr later
  const BACKEND_ENDPOINT = "/analyze/upload"; // <- ask Person 2 to match this route

  const HIGH_RISK_THRESHOLD = 71;

  // =========================
  // Utils
  // =========================
  function escapeHTML(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function closeModal() {
    document.getElementById("shieldlens-overlay")?.remove();
  }

  function riskBadgeText(score) {
    if (score >= 71) return `High Risk • ${score}/100`;
    if (score >= 31) return `Caution • ${score}/100`;
    return `Safe • ${score}/100`;
  }

  // Convert a File to base64 (for sending to backend)
  async function fileToBase64(file) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.slice(i, i + chunk));
    }
    return btoa(binary);
  }

  async function postJSON(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const t = await resp.text().catch(() => "");
      throw new Error(`HTTP ${resp.status}: ${t || resp.statusText}`);
    }
    return await resp.json();
  }

  // =========================
  // Modal UI (uses ui.css)
  // =========================
  function showModal({
    title = "ShieldLens",
    subtitle = "Real-time scan detected potential sensitive content.",
    riskScore = null,
    detailsTitle = "Detected",
    details = "",
    evidence = [],
    remediation = [],
    primaryText = null,        // e.g. "Scan with AI"
    primaryDisabled = false,
    onPrimary = null,
    onClose = null,
  } = {}) {
    closeModal();

    const overlay = document.createElement("div");
    overlay.id = "shieldlens-overlay";

    const modal = document.createElement("div");
    modal.id = "shieldlens-modal";

    const badge = riskScore === null
      ? `<div class="shieldlens-badge">Scan Result</div>`
      : `<div class="shieldlens-badge">${escapeHTML(riskBadgeText(Number(riskScore) || 0))}</div>`;

    const detailsHtml = details
      ? `<div class="shieldlens-section">
           <div style="font-weight:800; margin-bottom:6px;">${escapeHTML(detailsTitle)}</div>
           <div style="opacity:.95; line-height:1.35;">${escapeHTML(details)}</div>
         </div>`
      : "";

    const evidenceHtml = (Array.isArray(evidence) && evidence.length)
      ? `<div class="shieldlens-section">
           <div style="font-weight:800; margin-bottom:6px;">Evidence</div>
           <ul style="margin:0; padding-left:18px; opacity:.95; line-height:1.35;">
             ${evidence.slice(0, 6).map(s => `<li><code style="white-space:pre-wrap;">${escapeHTML(String(s))}</code></li>`).join("")}
           </ul>
         </div>`
      : "";

    const remediationHtml = (Array.isArray(remediation) && remediation.length)
      ? `<div class="shieldlens-section">
           <div style="font-weight:800; margin-bottom:6px;">Recommended Fix</div>
           <ul style="margin:0; padding-left:18px; opacity:.95; line-height:1.35;">
             ${remediation.slice(0, 6).map(s => `<li>${escapeHTML(String(s))}</li>`).join("")}
           </ul>
         </div>`
      : "";

    const primaryBtnHtml = primaryText
      ? `<button class="shieldlens-btn primary" id="shieldlens-primary" ${primaryDisabled ? "disabled" : ""} style="${primaryDisabled ? "opacity:.6; cursor:not-allowed;" : ""}">
           ${escapeHTML(primaryText)}
         </button>`
      : "";

    modal.innerHTML = `
      <div class="shieldlens-title">
        <div style="display:flex; flex-direction:column; gap:2px;">
          <div style="font-size:18px; font-weight:800;">${escapeHTML(title)}</div>
          <div style="opacity:.8; font-size:13px;">${escapeHTML(subtitle)}</div>
        </div>
        ${badge}
      </div>

      ${detailsHtml}
      ${evidenceHtml}
      ${remediationHtml}

      <div class="shieldlens-actions">
        ${primaryBtnHtml}
        <button class="shieldlens-btn" id="shieldlens-close">Close</button>
      </div>
    `;

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        closeModal();
        onClose?.();
      }
    });

    overlay.appendChild(modal);
    (document.body || document.documentElement).appendChild(overlay);

    modal.querySelector("#shieldlens-close")?.addEventListener("click", () => {
      closeModal();
      onClose?.();
    });

    modal.querySelector("#shieldlens-primary")?.addEventListener("click", async () => {
      if (primaryDisabled) return;
      await onPrimary?.();
    });
  }

  // =========================
  // Local Sensitivity Detection (fast MVP)
  // =========================
  function localSensitiveCheck(text) {
    const lower = text.toLowerCase();
    const hits = [];

    if (lower.includes("aws_secret_access_key")) hits.push("AWS Secret Access Key");
    if (lower.includes("aws_access_key_id")) hits.push("AWS Access Key ID");
    if (lower.includes("private_key")) hits.push("Private Key");
    if (lower.includes("api_key") || lower.includes("apikey")) hits.push("API Key");
    if (lower.includes("password")) hits.push("Password");

    if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) hits.push("SSN-like pattern (###-##-####)");
    if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) hits.push("AWS Key pattern (AKIA...)");

    return { looksSensitive: hits.length > 0, hits };
  }

  // =========================
  // Backend analysis (file -> base64 -> Gemini)
  // =========================
  function callBackendAnalyzeText({ text, filename, mime_type }) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      {
        type: "ANALYZE_TEXT",
        text,
        filename,
        mime_type,
        page_url: location.href,
      },
      (res) => {
        if (!res) return reject(new Error("No response from background"));
        if (!res.ok) return reject(new Error(res.error || "Backend error"));
        resolve(res.data);
      }
    );
  });
}

function callBackendAnalyzeFileBase64({ file_base64, filename, mime_type }) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      {
        type: "ANALYZE_FILE_BASE64",
        file_base64,
        filename,
        mime_type,
        page_url: location.href,
      },
      (res) => {
        if (!res) return reject(new Error("No response from background"));
        if (!res.ok) return reject(new Error(res.error || "Backend error"));
        resolve(res.data);
      }
    );
  });
}

  // =========================
  // FILE INTERCEPTION
  // =========================
  document.addEventListener(
    "change",
    async (e) => {
      const el = e.target;

      if (!(el instanceof HTMLInputElement)) return;
      if (el.type !== "file") return;
      if (!el.files || el.files.length === 0) return;

      const file = el.files[0];
      console.log("ShieldLens detected file upload:", file.name);

      // Read as text (works for txt/env; docx/pdf will look binary)
      let text = "";
      try {
        text = await file.text();
      } catch {
        text = "";
      }

      const isProbablyBinary =
        !text ||
        text.includes("\u0000") ||
        (file.type && !file.type.startsWith("text/") && !file.name.endsWith(".txt") && !file.name.endsWith(".env"));

      // ===== Binary files (DOCX/PDF): show modal with "Scan with AI" button =====
      if (isProbablyBinary) {
        showModal({
          title: "ShieldLens Notice",
          subtitle: "This file type cannot be scanned locally (binary format).",
          detailsTitle: "File",
          details: file.name,
          primaryText: USE_BACKEND ? "Scan with AI" : "Backend not ready",
          primaryDisabled: !USE_BACKEND,
          onPrimary: async () => {
            // Loading state
            showModal({
              title: "ShieldLens",
              subtitle: "Scanning with AI…",
              detailsTitle: "File",
              details: file.name,
              primaryText: null
            });

            try {
              const file_base64 = await fileToBase64(file);
              const report = await callBackendAnalyzeFileBase64({
                file_base64,
                filename: file.name,
                mime_type: file.type || "application/octet-stream",
              });

              const score = Number(report?.risk_score ?? report?.deepfake_percentage ?? 0);
              const types = Array.isArray(report?.detected_types) ? report.detected_types : [];
              const evidence = Array.isArray(report?.evidence_snippets) ? report.evidence_snippets : [];
              const remediation = Array.isArray(report?.remediation_steps) ? report.remediation_steps : [];
              const explanation = report?.explanation || report?.reasoning || "Scan complete.";

              showModal({
                title: score >= HIGH_RISK_THRESHOLD ? "Potential Sensitive Data Detected" : "Scan Complete",
                subtitle: explanation,
                riskScore: score,
                detailsTitle: "Detected Types",
                details: types.length ? types.join(", ") : "None",
                evidence,
                remediation
              });
            } catch (err) {
              console.error("Backend scan failed:", err);
              showModal({
                title: "ShieldLens Error",
                subtitle: "Could not reach scanning service.",
                detailsTitle: "Fix",
                details: "Check backend URL, endpoint, and CORS. Then try again.",
              });
            }
          }
        });
        return;
      }

      // ===== Text files: local scan first, optionally backend later =====
      try {
        const { looksSensitive, hits } = localSensitiveCheck(text || "");

        if (looksSensitive) {
          showModal({
            title: "Potential Sensitive Data Detected",
            subtitle: "Review before uploading.",
            riskScore: 85, // local demo score (backend will override later)
            detailsTitle: "Detected Types",
            details: hits.join(", "),
            primaryText: USE_BACKEND ? "Scan with AI" : null,
            primaryDisabled: !USE_BACKEND,
            onPrimary: async () => {
              showModal({
                title: "ShieldLens",
                subtitle: "Scanning with AI…",
                detailsTitle: "File",
                details: file.name
              });

              try {
                const report = await callBackendAnalyzeText({
                text,
                filename: file.name,
                mime_type: file.type || "text/plain",
              });

                const score = Number(report?.risk_score ?? 0);
                const types = Array.isArray(report?.detected_types) ? report.detected_types : [];
                const evidence = Array.isArray(report?.evidence_snippets) ? report.evidence_snippets : [];
                const remediation = Array.isArray(report?.remediation_steps) ? report.remediation_steps : [];
                const explanation = report?.explanation || "Scan complete.";

                showModal({
                  title: score >= HIGH_RISK_THRESHOLD ? "Potential Sensitive Data Detected" : "Scan Complete",
                  subtitle: explanation,
                  riskScore: score,
                  detailsTitle: "Detected Types",
                  details: types.length ? types.join(", ") : "None",
                  evidence,
                  remediation
                });
              } catch (err) {
                console.error("Backend scan failed:", err);
                showModal({
                  title: "ShieldLens Error",
                  subtitle: "Could not reach scanning service.",
                  detailsTitle: "Fix",
                  details: "Check backend URL, endpoint, and CORS. Then try again.",
                });
              }
            }
          });
        } else {
          console.log("ShieldLens: file seems safe (local check).");
        }
      } catch (err) {
        console.error("Local scan failed:", err);
      }
    },
    true
  );
})();
