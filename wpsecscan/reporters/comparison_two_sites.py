"""Side-by-side comparison of two sites' scans.

Round-64 #95 — useful for "is my new site better than the old one?" or
"is example.com better than competitor.com?" use cases.
"""
from __future__ import annotations

from html import escape


def compare_sites(site_a: tuple[str, dict], site_b: tuple[str, dict]) -> str:
    """Returns an HTML page comparing two sites.

    Each arg: (target_url, scan_report_dict-with-summary-key).
    """
    a_target, a_report = site_a
    b_target, b_report = site_b
    a_sum = a_report.get("summary", {}) if isinstance(a_report, dict) else {}
    b_sum = b_report.get("summary", {}) if isinstance(b_report, dict) else {}

    rows = []
    for sev in ("critical", "high", "medium", "low", "info"):
        a_n = int(a_sum.get(sev, 0))
        b_n = int(b_sum.get(sev, 0))
        winner = "tie"
        if a_n < b_n:
            winner = "A"
        elif b_n < a_n:
            winner = "B"
        rows.append(
            f"<tr><td>{escape(sev)}</td>"
            f"<td>{a_n}</td><td>{b_n}</td>"
            f"<td>{winner}</td></tr>"
        )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Comparison</title>
<style>
body {{ font-family: sans-serif; max-width: 800px; margin: 2em auto; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f7f7f7; }}
</style></head>
<body>
<h1>Side-by-side comparison</h1>
<p>Site A: <strong>{escape(a_target)}</strong><br>
   Site B: <strong>{escape(b_target)}</strong></p>
<table>
<thead><tr><th>Severity</th><th>A count</th><th>B count</th><th>Winner</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body></html>
"""
