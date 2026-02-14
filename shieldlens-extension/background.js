const API_BASE = "http://209.222.12.247:8000";

// Generic helper
async function postJSON(path, body) {
  const resp = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data?.detail || `HTTP ${resp.status}`);
  }
  return data;
}

// Listen for requests from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "ANALYZE_TEXT") {
        const data = await postJSON("/analyze/upload", {
          text: msg.text,
          filename: msg.filename || null,
          mime_type: msg.mime_type || "text/plain",
          page_url: msg.page_url || sender?.tab?.url || null,
        });
        sendResponse({ ok: true, data });
        return;
      }

      if (msg?.type === "ANALYZE_FILE_BASE64") {
        const data = await postJSON("/analyze/file_base64", {
          file_base64: msg.file_base64,
          filename: msg.filename || null,
          mime_type: msg.mime_type || "application/octet-stream",
          page_url: msg.page_url || sender?.tab?.url || null,
        });
        sendResponse({ ok: true, data });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (err) {
      sendResponse({ ok: false, error: String(err?.message || err) });
    }
  })();

  return true; // keep channel open for async response
});