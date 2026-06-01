"""Item #52 — board-room 1-page risk dashboard.

A single landscape sheet, three big numbers (current risk score / score
delta vs prior scan / open critical-and-high count), three short sentences
of plain-English summary, three action items the board should ratify.

Designed for printing on a single sheet of A4/letter as part of a board
pack. No tables, no per-finding detail — that's the auditor-PDF's job.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from ..models import ScanReport


def _prior_score(report: ScanReport) -> int | None:
    """Try to read the previous-scan risk_score from snapshot_history."""
    try:
        from .. import history as _h
        snaps = _h.snapshot_history(report.target)
        # The latest snapshot is THIS scan; the one before it is the
        # "prior" we compare to.
        if len(snaps) >= 2:
            prev = json.loads(snaps[-2].read_text(encoding="utf-8"))
            v = prev.get("risk_score")
            if isinstance(v, int):
                return v
    except (OSError, ValueError, ImportError, AttributeError):
        pass
    return None


def _bucket_message(score: int) -> tuple[str, str, str]:
    """Return (status_color, headline, three-action-bullets)."""
    if score >= 90:
        return (
            "#1f8a3c",
            "Posture is strong. Maintain the current operating cadence.",
            (
                "Keep monthly scans on the schedule.",
                "Maintain plugin auto-update where supported.",
                "Renew the next compliance review in 12 months.",
            ),
        )
    if score >= 70:
        return (
            "#c47700",
            "Posture is acceptable but with known gaps. Address within 30 days.",
            (
                "Patch high-severity findings inside the SLA window.",
                "Schedule a remediation review at the next ops meeting.",
                "Confirm backup off-site retention is current.",
            ),
        )
    if score >= 50:
        return (
            "#d35400",
            "Multiple material weaknesses present. Material remediation required.",
            (
                "Triage critical + high findings inside 7 days.",
                "Allocate dedicated remediation time in next sprint.",
                "Notify the board chair of any remaining open critical at next session.",
            ),
        )
    return (
        "#c0392b",
        "Significant material risk. Immediate remediation required.",
        (
            "Convene an emergency remediation huddle inside 48 hours.",
            "Halt non-essential change windows until critical findings close.",
            "Notify legal / data-controller per the incident-response policy.",
        ),
    )


def render(report: ScanReport) -> str:
    score = report.risk_score
    prior = _prior_score(report)
    if prior is None:
        delta_text = "—"
        delta_color = "#7f8c8d"
    else:
        delta = score - prior
        if delta > 0:
            delta_text = f"+{delta}"
            delta_color = "#1f8a3c"  # higher score = better
        elif delta < 0:
            delta_text = f"{delta}"
            delta_color = "#c0392b"
        else:
            delta_text = "0"
            delta_color = "#7f8c8d"

    s = report.summary
    crit_high = s.get("critical", 0) + s.get("high", 0)
    status_color, headline, actions = _bucket_message(score)

    summary_text = (
        f"Latest scan of <b>{html.escape(report.target)}</b> on "
        f"{html.escape(report.scanned_at)}. {headline} "
        f"There are <b>{crit_high}</b> critical-or-high open finding(s) "
        f"requiring action."
    )

    action_html = "".join(f"<li>{html.escape(a)}</li>" for a in actions)

    return f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>WPSecScan board summary — {html.escape(report.target)}</title>
<style>
  @page {{ size: A4 landscape; margin: 1cm; }}
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; color: #222; margin: 32px; }}
  h1 {{ font-size: 28pt; margin: 0; }}
  .meta {{ color: #555; font-size: 10pt; margin-bottom: 24px; }}
  .row {{ display: flex; gap: 24px; margin-bottom: 28px; }}
  .num {{ flex: 1; padding: 24px; border-radius: 12px; border: 2px solid #ddd; text-align: center; }}
  .num .big {{ font-size: 72pt; font-weight: 800; line-height: 1; }}
  .num .lab {{ font-size: 13pt; color: #555; margin-top: 6px; }}
  .num.score .big {{ color: {status_color}; }}
  .num.delta .big {{ color: {delta_color}; }}
  .num.openc .big {{ color: #c0392b; }}
  .summary {{ font-size: 14pt; line-height: 1.5; background: #fafafa; border-left: 4pt solid {status_color}; padding: 14px 20px; margin-bottom: 20px; }}
  h2 {{ font-size: 14pt; margin: 0 0 8px; }}
  ol {{ font-size: 12pt; line-height: 1.6; padding-left: 22px; }}
  .footer {{ font-size: 9pt; color: #999; margin-top: 28px; text-align: center; }}
  .noprint {{ background: #fffde7; border: 1px solid #fdd835; padding: 8px; margin-bottom: 12px; font-size: 9pt; }}
  @media print {{ .noprint {{ display: none; }} }}
</style>
</head><body>
<div class="noprint">Tip: open in your browser and <b>Print → Save as PDF</b> for the board pack.</div>
<h1>Security posture — board summary</h1>
<div class="meta">{html.escape(report.target)} · {html.escape(report.scanned_at)}</div>

<div class="row">
    <div class="num score"><div class="big">{score}</div><div class="lab">Risk score / 100</div></div>
    <div class="num delta"><div class="big">{delta_text}</div><div class="lab">vs prior scan</div></div>
    <div class="num openc"><div class="big">{crit_high}</div><div class="lab">Critical &amp; High open</div></div>
</div>

<div class="summary">{summary_text}</div>

<h2>Three actions the board should ratify</h2>
<ol>{action_html}</ol>

<div class="footer">Generated by WPSecScan — see the full HTML report for per-finding detail.</div>
</body></html>
"""


def write(report: ScanReport, path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(path, render(report))
