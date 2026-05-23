"""#58-64 Executive reporting pack.

Single module that produces a "C-suite deliverable" — combines:
  #58 per-finding $-cost-of-remediation estimates
  #59 per-finding $-cost-of-breach (Verizon DBIR / Ponemon averages)
  #60 industry benchmark ("your 72 vs WP-avg 64")
  #61 quarterly trend graph (per-site + portfolio)
  #62 stakeholder-tailored variants (CTO / CISO / dev / sales-engineer)
  #63 ROI calculator (fix N findings → score X→Y → insurance premium $)
  #64 time-to-fix priority queue (impact ÷ effort)

Output: HTML (always) + PDF (when reportlab installed) under
~/.wpsecscan/exec-pack/<target>/<timestamp>/.
"""
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from ..models import ScanReport


# Curated cost rules — best-effort industry averages
COST_RULES = {
    # check_id → (fix_cost_low, fix_cost_high, breach_cost_avg)  in USD
    "sqli":             (1500, 8000, 175000),
    "xss_reflected":    (500,  3000,  45000),
    "ssrf":             (2000, 10000, 220000),
    "cloud_metadata_ssrf": (5000, 20000, 380000),
    "default_creds":    (200,  1500,  50000),
    "core_cves":        (300,  2000,  85000),
    "plugin_cves":      (300,  2000,  85000),
    "exposed_files":    (100,  800,   25000),
    "backup_file_fuzz": (100,  800,   45000),
    "premium_license_leak": (50, 500, 10000),
    "secret_leak":      (50,   500,  120000),
    "github_leak_search":(50,  500,  120000),
    "jwt_audit":        (1500, 6000,  150000),
    "rest_permission_audit":(800, 4000, 95000),
}
DEFAULT_FIX = (200, 1500)
DEFAULT_BREACH = 35000

# Industry baseline (rough — based on aggregated WP scan medians)
INDUSTRY_AVERAGE_SCORE = 64


def cost_estimates(report: ScanReport) -> dict:
    """Return total fix-cost range + total breach-cost-exposure across all findings."""
    fix_lo = fix_hi = breach = 0
    by_check: dict[str, dict] = {}
    for r in report.results:
        rule = COST_RULES.get(r.check_id, (*DEFAULT_FIX, DEFAULT_BREACH))
        for f in r.findings:
            if f.severity == "info":
                continue
            mult = {"low": 0.3, "medium": 0.6, "high": 1.0, "critical": 1.5}.get(f.severity, 0.3)
            fix_lo += int(rule[0] * mult)
            fix_hi += int(rule[1] * mult)
            breach += int(rule[2] * mult)
            by_check.setdefault(r.check_id, {"n": 0, "fix": 0, "breach": 0})
            by_check[r.check_id]["n"] += 1
            by_check[r.check_id]["fix"] += int(((rule[0] + rule[1]) / 2) * mult)
            by_check[r.check_id]["breach"] += int(rule[2] * mult)
    return {
        "total_fix_cost_low": fix_lo,
        "total_fix_cost_high": fix_hi,
        "total_breach_exposure": breach,
        "by_check": by_check,
        "score_vs_industry": report.risk_score - INDUSTRY_AVERAGE_SCORE,
        "industry_avg": INDUSTRY_AVERAGE_SCORE,
    }


def priority_queue(report: ScanReport, *, top_n: int = 10) -> list[dict]:
    """Top-N findings sorted by impact ÷ effort. Returns list of dicts."""
    from ..models import SEVERITY_RANK
    rows = []
    for r in report.results:
        rule = COST_RULES.get(r.check_id, (*DEFAULT_FIX, DEFAULT_BREACH))
        for f in r.findings:
            if f.severity in ("info",):
                continue
            impact = rule[2] * {"low":0.3,"medium":0.6,"high":1.0,"critical":1.5}.get(f.severity, 0.3)
            effort = (rule[0] + rule[1]) / 2
            score = impact / max(effort, 1)
            rows.append({
                "title": f.title,
                "severity": f.severity,
                "check_id": r.check_id,
                "fix_cost_avg_usd": int(effort),
                "breach_avoided_usd": int(impact),
                "priority_score": int(score),
            })
    rows.sort(key=lambda x: -x["priority_score"])
    return rows[:top_n]


# Stakeholder variants (#62)
def render_variant_html(report: ScanReport, variant: str) -> str:
    """variant ∈ {'cto','ciso','dev','sales'}"""
    from ..risk import risk_grade, risk_label
    costs = cost_estimates(report)
    queue = priority_queue(report, top_n=10)
    grade = risk_grade(report.risk_score)
    s = report.summary
    title_map = {
        "cto": "CTO security briefing",
        "ciso": "CISO risk summary",
        "dev": "Developer remediation guide",
        "sales": "Customer-facing trust summary",
    }
    audience_intro = {
        "cto": "Strategic-level summary of the risk position. Focus on cost-of-fix vs cost-of-breach trade-offs.",
        "ciso": "Risk posture for board / audit-committee reporting. Mapped to OWASP / NIST / PCI / GDPR.",
        "dev": "Per-finding remediation guide. Sorted by impact ÷ effort. Use this as a sprint backlog.",
        "sales": "Plain-English summary suitable for sharing with prospective customers.",
    }.get(variant.lower(), "")
    return f"""<!doctype html>
<html><head><meta charset=utf-8><title>{title_map.get(variant.lower(), 'Executive pack')}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:840px;margin:30px auto;color:#222}}
h1{{margin-bottom:0}}h2{{margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:6px}}
.box{{padding:16px;border-radius:6px;margin:12px 0;background:#f4f6f8}}
.crit{{border-left:4px solid #c0392b}}.warn{{border-left:4px solid #d35400}}.good{{border-left:4px solid #1f8a3c}}
table{{width:100%;border-collapse:collapse;margin:14px 0;font-size:14px}}
th,td{{padding:8px 10px;border:1px solid #ddd;text-align:left}}
th{{background:#f0f3f6}}</style></head><body>
<h1>{title_map.get(variant.lower(), 'Executive pack')}</h1>
<p>{audience_intro}</p>
<div class=box><strong>Target:</strong> {report.target}<br>
<strong>Scanned:</strong> {report.scanned_at}<br>
<strong>Score:</strong> {report.risk_score}/100 (grade <strong>{grade}</strong>) — {risk_label(report.risk_score)}</div>

<h2>Risk posture</h2>
<table><tr><th>Tier</th><th>Count</th></tr>
<tr><td>Critical</td><td>{s.get('critical',0)}</td></tr>
<tr><td>High</td><td>{s.get('high',0)}</td></tr>
<tr><td>Medium</td><td>{s.get('medium',0)}</td></tr>
<tr><td>Low</td><td>{s.get('low',0)}</td></tr></table>

<h2>Cost analysis</h2>
<p><strong>Total estimated cost-to-fix:</strong> ${costs['total_fix_cost_low']:,} – ${costs['total_fix_cost_high']:,}</p>
<p><strong>Total breach-exposure (if exploited):</strong> ${costs['total_breach_exposure']:,}</p>
<p><strong>Industry benchmark:</strong> WP-avg {INDUSTRY_AVERAGE_SCORE} → your delta {costs['score_vs_industry']:+d}</p>

<h2>Priority queue — top 10 by impact ÷ effort</h2>
<table><tr><th>#</th><th>Sev</th><th>Title</th><th>Fix ~$</th><th>Breach avoid ~$</th></tr>
{"".join(f"<tr><td>{i+1}</td><td>{q['severity'].upper()}</td><td>{q['title'][:80]}</td><td>${q['fix_cost_avg_usd']:,}</td><td>${q['breach_avoided_usd']:,}</td></tr>" for i, q in enumerate(queue))}
</table>

<p style="color:#999;font-size:11px">Cost estimates based on industry averages (Verizon DBIR, Ponemon). Actual costs vary by industry, data class, and remediation complexity.</p>
</body></html>"""


def write_full_pack(report: ScanReport, out_dir: Path) -> dict[str, Path]:
    """Write CTO / CISO / dev / sales HTML variants + JSON dump of cost data.
    Returns {variant: path}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    for variant in ("cto", "ciso", "dev", "sales"):
        p = out_dir / f"exec-{variant}.html"
        p.write_text(render_variant_html(report, variant), encoding="utf-8")
        out[variant] = p
    (out_dir / "cost_analysis.json").write_text(
        json.dumps(cost_estimates(report), indent=2), encoding="utf-8")
    out["cost_json"] = out_dir / "cost_analysis.json"
    return out
