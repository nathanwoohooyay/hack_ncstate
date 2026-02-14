async function scanVideo(video) {
  try {
    // Show UI
    showLoading(video);

    // Get frames from the video
    const frames = await captureFrames(video);

    if (!frames || frames.length === 0) {
      throw new Error("No frames captured from video");
    }

    // Send frames to backend deepfake endpoint
    const res = await fetch("https://YOUR_VULTR_API/analyze/deepfake", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        frames: frames,
        frame_count: frames.length,
        page_url: window.location.href
      })
    });

    // Work w/ backend errors
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Backend error (${res.status}): ${errText}`);
    }

    // Parse backend response
    const result = await res.json();

    // Display result in UI
    showResult(video, result);

  } catch (err) {
    console.error("ShieldLens deepfake scan failed:", err);

    showResult(video, {
      deepfake_percentage: 0,
      explanation: "Deepfake analysis failed or was interrupted.",
      recommendation: "Please try again or verify the source manually."
    });
  }
}
