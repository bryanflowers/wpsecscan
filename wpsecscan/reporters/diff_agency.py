"""Item #55 — diff two agency dashboards.

`wpsecscan diff-agency old-dashboard.html new-dashboard.html [--out diff.html]`

Each agency dashboard embeds a machine-readable manifest in
`<script type="application/json" id="wpsecscan-dashboard-data">`. We
extract both manifests and produce a side-by-side comparison: sites
added, sites removed, score deltas per site, and totals delta. Useful
for month-over-month portfolio reviews.

For older dashboards that predate the embedded manifest (renderered
before this commit) we fall back to a minimal HTML-table scrape so the
operator still gets a comparison instead of an error.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

_MANIFEST_RE = re.compile(
    r'<script[^>]*id="wpsecscan-dashboard-data"[^>]*>(.*?)</script>',
    re.DOTALL,
)


def _extract_manifest(html_text: str) -> dict[str, Any]:
    m = _MANIFEST_RE.search(html_text)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass
    # Fallback: scrape <tr>…<td>target</td>…<td>SCORE/100</td> rows. Crude
    # but salvages comparisons of pre-#55 dashboards.
    sites = []
    # match <td>target_value</td>...<td class="num">87/100</td>
    row_re = re.compile(
        r"<tr>.*?<td>([^<]+)</td>.*?<td[^>]*>(\d{1,3})/100</td>",
        re.DOTALL,
    )
    for tgt, score in row_re.findall(html_text):
        sites.append({"target": tgt.strip(), "risk_score": int(score),
                      "worst": None, "summary": {}})
    return {"generated_at": "", "totals": {}, "sites": sites}


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_by = {s["target"]: s for s in old.get("sites", [])}
    new_by = {s["target"]: s for s in new.get("sites", [])}

    added = sorted(set(new_by) - set(old_by))
    removed = sorted(set(old_by) - set(new_by))
    changed = []
    for tgt in sorted(set(old_by) & set(new_by)):
        o, n = old_by[tgt], new_by[tgt]
        score_d = (n.get("risk_score") or 0) - (o.get("risk_score") or 0)
        if score_d != 0 or o.get("worst") != n.get("worst"):
            changed.append({
                "target": tgt,
                "old_score": o.get("risk_score"),
                "new_score": n.get("risk_score"),
                "delta": score_d,
                "old_worst": o.get("worst"),
                "new_worst": n.get("worst"),
            })

    def _tot(d: dict, k: str) -> int:
        return int((d.get("totals") or {}).get(k, 0))

    totals_delta = {
        k: _tot(new, k) - _tot(old, k)
        for k in ("critical", "high", "medium", "low", "info")
    }

    return {
        "old_at": old.get("generated_at", ""),
        "new_at": new.get("generated_at", ""),
        "added": [new_by[t] for t in added],
        "removed": [old_by[t] for t in removed],
        "changed": changed,
        "totals_delta": totals_delta,
        "site_count_old": len(old_by),
        "site_count_new": len(new_by),
    }


def render_html(d: dict[str, Any]) -> str:
    def _row_changed(c: dict) -> str:
        sign = "+" if c["delta"] > 0 else ""
        color = "#1f8a3c" if c["delta"] > 0 else "#c0392b"
        return (
            f"<tr><td>{html.escape(c['target'])}</td>"
            f"<td>{c['old_score']}</td><td>{c['new_score']}</td>"
            f"<td style='color:{color};font-weight:700'>{sign}{c['delta']}</td>"
            f"<td>{html.escape(str(c['old_worst'] or '—'))}</td>"
            f"<td>{html.escape(str(c['new_worst'] or '—'))}</td></tr>"
        )

    def _row_added(s: dict) -> str:
        return (f"<tr><td>{html.escape(s['target'])}</td>"
                f"<td>{s.get('risk_score','—')}</td>"
                f"<td>{html.escape(str(s.get('worst') or '—'))}</td></tr>")

    def _row_removed(s: dict) -> str:
        return _row_added(s)

    td = d["totals_delta"]
    totals_pills = " ".join(
        f"<span class='pill'>{k}: {'+' if td[k] > 0 else ''}{td[k]}</span>"
        for k in ("critical", "high", "medium", "low", "info")
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>WPSecScan — dashboard diff</title>
<style>
  body {{ font: 13px -apple-system, "Segoe UI", sans-serif; color:#222; margin:24px; }}
  h1 {{ font-size:18pt; margin:0 0 6px; }}
  .meta {{ color:#555; font-size:10pt; margin-bottom:18px; }}
  h2 {{ font-size:13pt; border-bottom:1px solid #ddd; padding-bottom:4px; margin-top:22px; }}
  table {{ border-collapse:collapse; width:100%; margin-top:6px; }}
  th,td {{ border:1px solid #ddd; padding:5px 8px; text-align:left; font-size:11pt; }}
  th {{ background:#34495e; color:#fff; }}
  .empty {{ color:#888; font-style:italic; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px;
          background:#eee; font-size:10pt; margin-right:6px; }}
</style></head><body>
<h1>Agency dashboard diff</h1>
<div class="meta">
    <b>Before:</b> {html.escape(d['old_at'] or 'unknown')} ·
    <b>After:</b> {html.escape(d['new_at'] or 'unknown')}<br>
    Sites: {d['site_count_old']} → {d['site_count_new']} · Totals delta: {totals_pills}
</div>

<h2>Score / severity changes ({len(d['changed'])})</h2>
{('<table><thead><tr><th>Site</th><th>Old score</th><th>New score</th><th>Δ</th>'
  '<th>Old worst</th><th>New worst</th></tr></thead><tbody>'
  + ''.join(_row_changed(c) for c in d['changed']) + '</tbody></table>'
  ) if d['changed'] else '<p class="empty">No score or severity changes.</p>'}

<h2>Sites added ({len(d['added'])})</h2>
{('<table><thead><tr><th>Site</th><th>Score</th><th>Worst</th></tr></thead><tbody>'
  + ''.join(_row_added(s) for s in d['added']) + '</tbody></table>'
  ) if d['added'] else '<p class="empty">None.</p>'}

<h2>Sites removed ({len(d['removed'])})</h2>
{('<table><thead><tr><th>Site</th><th>Score</th><th>Worst</th></tr></thead><tbody>'
  + ''.join(_row_removed(s) for s in d['removed']) + '</tbody></table>'
  ) if d['removed'] else '<p class="empty">None.</p>'}

</body></html>
"""


def write(old_html_path: Path, new_html_path: Path, out_path: Path) -> dict[str, Any]:
    old = _extract_manifest(Path(old_html_path).read_text(encoding="utf-8"))
    new = _extract_manifest(Path(new_html_path).read_text(encoding="utf-8"))
    d = diff(old, new)
    out_path.write_text(render_html(d), encoding="utf-8")
    return d
