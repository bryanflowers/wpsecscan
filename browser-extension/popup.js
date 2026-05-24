// Round-64 #166 — WPSecScan browser-extension popup
// Calls the local daemon at http://localhost:8080

const DAEMON_URL = "http://localhost:8080";

document.getElementById("scan").addEventListener("click", async () => {
  const status = document.getElementById("status");
  const summary = document.getElementById("summary");
  status.textContent = "Starting scan...";

  // Get the active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const target = tab.url;

  try {
    // Start scan
    const startResp = await fetch(`${DAEMON_URL}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!startResp.ok) throw new Error(`Daemon returned ${startResp.status}`);
    const { scan_id } = await startResp.json();
    status.textContent = `Scan ${scan_id} running...`;

    // Poll for completion
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const r = await fetch(`${DAEMON_URL}/scans/${scan_id}`);
      if (!r.ok) continue;
      const data = await r.json();
      if (data.status === "complete") {
        status.textContent = "Done.";
        summary.textContent = JSON.stringify(data.summary, null, 2);
        return;
      }
      status.textContent = `Scan running... (${i + 1}/120)`;
    }
    status.textContent = "Timeout waiting for scan.";
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
  }
});
