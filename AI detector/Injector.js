// Detect The video
function findVideos() {
  return Array.from(document.querySelectorAll("video"))
    .filter(v => v.videoWidth > 0 && v.videoHeight > 0);
}
// Scan video
function addScanButton(video) {
  if (video.dataset.shieldlensAttached) return;
  video.dataset.shieldlensAttached = "true";

  const btn = document.createElement("button");
  btn.innerText = "Scan Video";
  btn.onclick = () => scanVideo(video);

  Object.assign(btn.style, {
    position: "absolute",
    top: "10px",
    left: "10px",
    zIndex: "9999",
    background: "#111",
    color: "#fff",
    padding: "6px 10px",
    borderRadius: "6px",
    cursor: "pointer"
  });

  video.parentElement.style.position = "relative";
  video.parentElement.appendChild(btn);
}

// Get the frames to be sent to back end
// 