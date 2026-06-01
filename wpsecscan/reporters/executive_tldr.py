"""C57 (v2.7.0) — 3-sentence executive TL;DR.

Deterministic builder (no AI required) for an email-subject-shaped
3-sentence summary at the top of every report. Designed for forwarding
in a 60-character email subject + a 280-character first body line.

Sentence 1: current score + worst severity + trend signal.
Sentence 2: top-2 findings the operator should act on.
Sentence 3: next recommended action.
"""
from __future__ import annotations

from ..models import ScanReport


def _grade(score: int) -> str:
    if score >= 95: return "A"
    if score >= 85: return "B"
    if score >= 70: return "C"
    if score >= 50: return "D"
    return "F"


def build(report: ScanReport) -> str:
    s = report.summary
    crit = s.get("critical", 0)
    high = s.get("high", 0)
    score = report.risk_score
    grade = _grade(score)
    worst = report.worst_severity() or "info"

    # Sentence 1
    s1 = (
        f"Posture score {score}/100 (grade {grade}); worst severity "
        f"observed: {worst}; {crit} critical and {high} high finding(s)."
    )

    # Sentence 2 — top-2 findings
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings = sorted(
        report.all_findings,
        key=lambda f: severity_rank.get(f.severity, 5),
    )[:2]
    if all_findings:
        top_titles = " / ".join(f.title[:80] for f in all_findings)
        s2 = f"Top items: {top_titles}."
    else:
        s2 = "No actionable findings detected."

    # Sentence 3
    if crit:
        s3 = "Remediate critical findings inside 48 hours per the SLA tracker."
    elif high:
        s3 = "Schedule a 7-day remediation window for the high-severity items."
    elif score < 80:
        s3 = "Multiple medium / low findings — plan a 30-day clean-up sprint."
    else:
        s3 = "Maintain current scan cadence; no immediate action required."

    return f"{s1} {s2} {s3}"


def render_html(report: ScanReport) -> str:
    """Return the HTML block to embed at the very top of every report."""
    tldr = build(report)
    return (
        '<div class="exec-tldr" role="region" aria-label="Executive summary" '
        'style="background:#fff8dc;border-left:4pt solid #f1c40f;'
        'padding:14px 18px;margin:0 0 16px;font-size:13pt;line-height:1.5">'
        f'<b>TL;DR:</b> {tldr}</div>'
    )


def write(report: ScanReport, out_path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(out_path, build(report) + "\n")
