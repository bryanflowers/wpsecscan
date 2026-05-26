(async () => {
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  const url = tab && tab.url ? new URL(tab.url) : null;
  const host = url ? url.host : '(no active tab)';
  document.getElementById('host').textContent = 'Active host: ' + host;

  document.getElementById('file').addEventListener('change', async (ev) => {
    const f = ev.target.files[0];
    if (!f) return;
    const text = await f.text();
    let report;
    try { report = JSON.parse(text); }
    catch (e) {
      document.getElementById('status').textContent = 'Bad JSON: ' + e.message;
      return;
    }
    chrome.runtime.sendMessage({type: 'load_report', host, report}, (resp) => {
      if (resp && resp.ok) {
        document.getElementById('status').textContent =
          'Loaded ' + (report.results || []).length + ' check result(s) for ' + host +
          '. Refresh wp-admin to see the overlay.';
      } else {
        document.getElementById('status').textContent = 'Failed to save report.';
      }
    });
  });
})();
