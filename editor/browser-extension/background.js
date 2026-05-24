// WPSecScan launcher — Chrome/Firefox extension background worker.
// Right-click a page → "Scan with WPSecScan" → POSTs to the local API server.

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "wpsecscan-scan",
    title: "Scan with WPSecScan",
    contexts: ["page", "link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.linkUrl || info.pageUrl || tab.url;
  if (!url) return;
  const { apiUrl = "http://localhost:8765" } = await chrome.storage.sync.get(["apiUrl"]);
  try {
    const r = await fetch(`${apiUrl}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: url }),
    });
    if (!r.ok) {
      chrome.notifications?.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "WPSecScan",
        message: `Scan request failed: ${r.status}`,
      });
      return;
    }
    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icon.png",
      title: "WPSecScan",
      message: `Scan queued for ${url}`,
    });
  } catch (e) {
    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icon.png",
      title: "WPSecScan",
      message: "Cannot reach WPSecScan API — start the daemon first.",
    });
  }
});
