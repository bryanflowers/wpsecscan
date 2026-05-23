"""E4 Two-report HTML diff viewer.

Generates a single standalone .html file that uses <input type=file>
selectors so the user can drop in two WPSecScan JSON reports and see them
side-by-side with new/fixed/changed highlighting.

No server, no JS bundle, no dependency on a specific filesystem path —
ideal for emailing along with two JSON exports.
"""
from __future__ import annotations

from pathlib import Path


_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WPSecScan — Report diff viewer</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;
        --new:#5a1816;--gone:#0c2a18;--same:#161b22;
        --new-fg:#ffd6d6;--gone-fg:#cfe5d0;--same-fg:#8b949e}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.5 -apple-system,Segoe UI,system-ui,sans-serif}
  header{padding:18px 22px;border-bottom:1px solid var(--border);background:var(--panel)}
  header h1{margin:0 0 6px;font-size:18px}
  .picker{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px}
  .picker label{flex:1;min-width:280px;background:var(--panel);border:1px dashed var(--border);
    border-radius:8px;padding:14px;cursor:pointer}
  .picker label:hover{border-color:#79c0ff}
  .picker .name{color:var(--muted);font-size:12px;margin-top:4px}
  main{max-width:1300px;margin:0 auto;padding:18px 22px}
  .summary{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}
  .stat{padding:10px 16px;border-radius:6px;border:1px solid var(--border);background:var(--panel)}
  .stat .n{font-size:22px;font-weight:700;display:block}
  .stat.new{border-color:#7a1d1d;background:var(--new);color:var(--new-fg)}
  .stat.gone{border-color:#1b5e2a;background:var(--gone);color:var(--gone-fg)}
  .stat.same{color:var(--same-fg)}
  table{width:100%;border-collapse:collapse;margin-top:14px;background:var(--panel);border:1px solid var(--border)}
  th,td{border:1px solid var(--border);padding:8px 10px;vertical-align:top;text-align:left;font-size:13px}
  th{background:#1f2630;color:#79c0ff}
  tr.new{background:rgba(122,29,29,0.18)}
  tr.gone{background:rgba(27,94,42,0.18)}
  .sev{font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 6px;border-radius:3px}
  .sev.critical{background:#67000d;color:#ffd6d6}
  .sev.high{background:#5a1816;color:#ff8a85}
  .sev.medium{background:#4a3a10;color:#f0c674}
  .sev.low{background:#133246;color:#79c0ff}
  .sev.info{background:#21262d;color:#8b949e}
  .tag{display:inline-block;padding:1px 6px;border-radius:3px;background:#1f2630;color:var(--muted);font-size:11px;margin-left:4px}
  .empty{color:var(--muted);font-style:italic;padding:14px;text-align:center}
  details summary{cursor:pointer;font-weight:600}
  .label-a{color:#79c0ff} .label-b{color:#f0c674}
</style>
</head>
<body>
<header>
  <h1>WPSecScan — Report diff viewer</h1>
  <div class="picker">
    <label>
      <div>📁 <span class="label-a">A — baseline report</span> (older / previous run)</div>
      <div class="name" id="name-a">click to choose a WPSecScan JSON file…</div>
      <input type="file" id="file-a" accept=".json,application/json" style="display:none">
    </label>
    <label>
      <div>📁 <span class="label-b">B — current report</span> (newer / latest run)</div>
      <div class="name" id="name-b">click to choose a WPSecScan JSON file…</div>
      <input type="file" id="file-b" accept=".json,application/json" style="display:none">
    </label>
  </div>
</header>
<main>
  <div id="meta" class="empty">Load both reports above to see the diff.</div>
  <div id="summary" class="summary" hidden></div>
  <div id="diff"></div>
</main>
<script>
(function(){
  const els = {
    nameA: document.getElementById('name-a'),
    nameB: document.getElementById('name-b'),
    fileA: document.getElementById('file-a'),
    fileB: document.getElementById('file-b'),
    meta: document.getElementById('meta'),
    summary: document.getElementById('summary'),
    diff: document.getElementById('diff'),
  };
  const state = { a: null, b: null };

  document.querySelectorAll('label[for]').forEach(()=>{});
  document.querySelectorAll('label').forEach((l, i) => {
    const inp = l.querySelector('input');
    if (!inp) return;
    l.addEventListener('click', ()=> inp.click());
  });

  function read(side, file) {
    const r = new FileReader();
    r.onload = (e) => {
      try {
        state[side] = JSON.parse(e.target.result);
        (side === 'a' ? els.nameA : els.nameB).textContent = file.name + ' — loaded';
        if (state.a && state.b) render();
      } catch (err) {
        alert('Failed to parse ' + file.name + ': ' + err.message);
      }
    };
    r.readAsText(file);
  }
  els.fileA.addEventListener('change', e => e.target.files[0] && read('a', e.target.files[0]));
  els.fileB.addEventListener('change', e => e.target.files[0] && read('b', e.target.files[0]));

  function findingKey(check_id, f) {
    // Title + severity is the stable identifier across runs (urls drift).
    return (check_id || '?') + '|' + (f.severity||'') + '|' + (f.title||'');
  }
  function collect(report) {
    const map = new Map();
    (report.results || []).forEach(r => {
      (r.findings || []).forEach(f => map.set(findingKey(r.check_id, f),
        Object.assign({_check_id: r.check_id, _check_name: r.check_name || r.check_id}, f)));
    });
    return map;
  }
  function escape(s) {
    return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }
  function row(f, cls) {
    return `<tr class="${cls}"><td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td>${escape(f.title)}<span class="tag">${escape(f._check_name)}</span></td>
      <td>${escape((f.url||'').slice(0,80))}</td></tr>`;
  }
  function render() {
    const A = collect(state.a), B = collect(state.b);
    const added = [], removed = [], same = [];
    B.forEach((f,k) => A.has(k) ? same.push(f) : added.push(f));
    A.forEach((f,k) => B.has(k) || removed.push(f));

    els.meta.hidden = true;
    els.summary.hidden = false;
    const aScore = state.a.risk_score ?? '?', bScore = state.b.risk_score ?? '?';
    const aTime = state.a.scanned_at || '?', bTime = state.b.scanned_at || '?';
    els.summary.innerHTML = `
      <div class="stat new"><span class="n">${added.length}</span>NEW in B</div>
      <div class="stat gone"><span class="n">${removed.length}</span>FIXED in B</div>
      <div class="stat same"><span class="n">${same.length}</span>UNCHANGED</div>
      <div class="stat"><span class="n">${aScore} → ${bScore}</span>risk score (A → B)</div>
      <div class="stat"><span class="n" style="font-size:12px">${escape(aTime)}<br>${escape(bTime)}</span>A / B scanned at</div>
    `;
    const sevRank = {critical:4,high:3,medium:2,low:1,info:0};
    function sortBySev(arr) { arr.sort((x,y) => (sevRank[y.severity]||0)-(sevRank[x.severity]||0)); }
    sortBySev(added); sortBySev(removed); sortBySev(same);

    let html = '';
    if (added.length) {
      html += '<h2 style="color:#ff8a85">🆕 New findings in B (' + added.length + ')</h2>';
      html += '<table><tr><th>Sev</th><th>Title</th><th>URL</th></tr>'
            + added.map(f => row(f,'new')).join('') + '</table>';
    }
    if (removed.length) {
      html += '<h2 style="color:#6cc474">✅ Fixed since A (' + removed.length + ')</h2>';
      html += '<table><tr><th>Sev</th><th>Title</th><th>URL</th></tr>'
            + removed.map(f => row(f,'gone')).join('') + '</table>';
    }
    if (same.length) {
      html += '<details style="margin-top:18px"><summary>Unchanged (' + same.length + ')</summary>';
      html += '<table><tr><th>Sev</th><th>Title</th><th>URL</th></tr>'
            + same.map(f => row(f,'')).join('') + '</table></details>';
    }
    if (!added.length && !removed.length) {
      html = '<div class="empty">No additions or removals — reports match.</div>' + html;
    }
    els.diff.innerHTML = html;
  }
})();
</script>
</body>
</html>
"""


def write(path: Path) -> None:
    """Write the standalone diff viewer to disk."""
    path.write_text(_HTML, encoding="utf-8")


def render() -> str:
    """Return the HTML as a string (no I/O)."""
    return _HTML
