// Injected into every wp-admin page. Pulls the saved report for this
// host, then overlays an "issues" pill on the admin bar that opens a
// side-panel listing the findings WPSecScan saw for this URL.
(async () => {
  const host = location.host;
  const report = await new Promise((resolve) => {
    chrome.runtime.sendMessage({type: 'get_report', host}, (r) => resolve(r));
  });
  if (!report || !Array.isArray(report.results)) return;

  // Match findings whose `url` overlaps with the current page path.
  const here = location.href;
  const here_path = location.pathname;
  const relevant = [];
  for (const result of report.results) {
    for (const f of (result.findings || [])) {
      const u = f.url || '';
      if (!u) continue;
      if (here.startsWith(u) || u.startsWith(here)
          || (u.includes(here_path) && here_path.length > 1)) {
        relevant.push({...f, check_id: result.check_id});
      }
    }
  }
  if (relevant.length === 0) return;

  // Build a small floating pill (use admin-bar if available, else fixed).
  const pill = document.createElement('div');
  pill.id = 'wpsecscan-overlay-pill';
  pill.className = 'wpsecscan-pill';
  const worst = ['critical','high','medium','low','info'].find(s => relevant.some(f => f.severity === s)) || 'info';
  pill.dataset.severity = worst;
  pill.textContent = `WPSecScan: ${relevant.length} issue${relevant.length===1?'':'s'} (worst: ${worst})`;
  pill.addEventListener('click', () => panel.style.display = panel.style.display === 'block' ? 'none' : 'block');
  document.body.appendChild(pill);

  const panel = document.createElement('div');
  panel.id = 'wpsecscan-overlay-panel';
  panel.className = 'wpsecscan-panel';
  panel.innerHTML = `<h3>WPSecScan findings on this page</h3>
                       <ul>` +
    relevant.map(f => `<li class="sev-${f.severity}"><b>${f.severity.toUpperCase()}</b>: ${escapeHtml(f.title)}<br><small>check_id: ${f.check_id}</small></li>`).join('')
    + `</ul>`;
  document.body.appendChild(panel);

  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }
})();
