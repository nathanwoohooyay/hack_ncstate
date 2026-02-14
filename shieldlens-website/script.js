document.getElementById("copyTest")?.addEventListener("click", async () => {
  const text = document.getElementById("testText")?.innerText || "";
  try {
    await navigator.clipboard.writeText(text);
    const btn = document.getElementById("copyTest");
    if (btn) {
      const old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = old), 900);
    }
  } catch {
    alert("Clipboard blocked. Copy manually from the code block.");
  }
});
