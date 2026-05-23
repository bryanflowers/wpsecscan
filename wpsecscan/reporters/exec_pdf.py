"""E1 Executive PDF — a one-page non-technical summary suitable for sharing
with managers / clients.

Uses reportlab if installed (true PDF). Otherwise writes a print-friendly
HTML page that the user can open in a browser and Ctrl+P → "Save as PDF".

The exec PDF deliberately omits per-finding evidence and remediation — that
belongs in the full HTML report. This is just: risk score, grade, summary
counts, top 5 issues by severity, and "what to do next" callouts.
"""
from __future__ import annotations

import html as _html
from pathlib import Path

from ..models import ScanReport, Finding


def _top_findings(report: ScanReport, limit: int = 5) -> list[Finding]:
    from ..models import SEVERITY_RANK
    flat: list[Finding] = []
    for res in report.results:
        flat.extend(res.findings)
    flat.sort(key=lambda f: -SEVERITY_RANK.get(f.severity, -1))
    return [f for f in flat if f.severity in ("critical", "high", "medium")][:limit]


def _summary_strip(report: ScanReport) -> str:
    s = report.summary
    return (
        f"{s.get('critical', 0)} critical · {s.get('high', 0)} high · "
        f"{s.get('medium', 0)} medium · {s.get('low', 0)} low · {s.get('info', 0)} info"
    )


def _has_reportlab() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def _render_pdf_reportlab(report: ScanReport, path: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.enums import TA_LEFT
    from ..risk import risk_grade, risk_label, risk_tier

    score = report.risk_score
    tier = risk_tier(score)
    tier_color = {"green": "#1f8a3c", "yellow": "#c47700", "orange": "#d35400", "red": "#c0392b"}[tier]

    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Title"], fontSize=22, alignment=TA_LEFT, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, spaceAfter=4)
    score_para = ParagraphStyle("score", parent=styles["Title"], fontSize=42,
                                textColor=HexColor(tier_color), alignment=TA_LEFT, spaceAfter=4)
    grade_para = ParagraphStyle("grade", parent=styles["Title"], fontSize=18,
                                textColor=HexColor(tier_color), alignment=TA_LEFT, spaceAfter=2)

    doc = SimpleDocTemplate(str(path), pagesize=letter,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    flow: list = []
    flow.append(Paragraph("WPSecScan Executive Summary", title))
    flow.append(Paragraph(f"<b>Target:</b> {_html.escape(report.target)}", body))
    flow.append(Paragraph(f"<b>Scanned:</b> {_html.escape(report.scanned_at)}", body))
    flow.append(Spacer(1, 0.15 * inch))

    flow.append(Paragraph(f"{score}/100", score_para))
    flow.append(Paragraph(f"Grade <b>{risk_grade(score)}</b> — {risk_label(score)}", grade_para))
    flow.append(Spacer(1, 0.1 * inch))

    s = report.summary
    counts_table = Table(
        [["Critical", "High", "Medium", "Low", "Info"],
         [str(s.get("critical", 0)), str(s.get("high", 0)), str(s.get("medium", 0)),
          str(s.get("low", 0)), str(s.get("info", 0))]],
        colWidths=[1.2 * inch] * 5,
    )
    counts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), HexColor("#c0392b")),
        ("BACKGROUND", (1, 0), (1, 0), HexColor("#d35400")),
        ("BACKGROUND", (2, 0), (2, 0), HexColor("#c47700")),
        ("BACKGROUND", (3, 0), (3, 0), HexColor("#7f8c8d")),
        ("BACKGROUND", (4, 0), (4, 0), HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 20),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING", (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#bdc3c7")),
    ]))
    flow.append(counts_table)
    flow.append(Spacer(1, 0.25 * inch))

    top = _top_findings(report)
    if top:
        flow.append(Paragraph("Top issues", h2))
        rows = [["Severity", "Issue"]]
        for f in top:
            rows.append([f.severity.upper(), _html.escape(f.title[:120])])
        t = Table(rows, colWidths=[1.0 * inch, 5.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#34495e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#bdc3c7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#ffffff"), HexColor("#f4f6f7")]),
        ]))
        flow.append(t)
        flow.append(Spacer(1, 0.2 * inch))

    flow.append(Paragraph("What to do next", h2))
    if score < 50:
        next_text = ("Significant exposure detected. Triage all critical and high findings within 24-48h. "
                     "Review the full HTML report for remediation steps per finding.")
    elif score < 70:
        next_text = ("Multiple issues that warrant prompt attention. Prioritize the high and critical "
                     "findings; medium-severity issues should be scheduled within the next sprint.")
    elif score < 90:
        next_text = ("A few issues exist but no critical exposure. Address them at your normal cadence.")
    else:
        next_text = ("No actionable findings. Re-scan after any plugin / theme update.")
    flow.append(Paragraph(next_text, body))

    flow.append(Spacer(1, 0.4 * inch))
    flow.append(Paragraph(
        "<i>Generated by WPSecScan — open the full HTML report for per-finding evidence and "
        "remediation guidance.</i>", body))

    doc.build(flow)


def _render_pdf_html_fallback(report: ScanReport, path: Path) -> None:
    """Print-friendly HTML page when reportlab isn't installed."""
    from ..risk import risk_grade, risk_label, risk_tier
    score = report.risk_score
    tier = risk_tier(score)
    color = {"green": "#1f8a3c", "yellow": "#c47700", "orange": "#d35400", "red": "#c0392b"}[tier]

    top = _top_findings(report)
    top_rows = "".join(
        f"<tr><td class='sev sev-{f.severity}'>{f.severity.upper()}</td>"
        f"<td>{_html.escape(f.title)}</td></tr>"
        for f in top
    ) or "<tr><td colspan=2>No high-severity findings.</td></tr>"

    if score < 50:
        next_text = ("Significant exposure detected. Triage all critical and high findings within 24-48h. "
                     "Review the full HTML report for remediation steps per finding.")
    elif score < 70:
        next_text = ("Multiple issues that warrant prompt attention. Prioritize high and critical findings.")
    elif score < 90:
        next_text = "A few issues exist but no critical exposure. Address them at your normal cadence."
    else:
        next_text = "No actionable findings. Re-scan after any plugin / theme update."

    s = report.summary
    doc = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>WPSecScan Executive Summary — {_html.escape(report.target)}</title>
<style>
  @page {{ size: letter; margin: 0.6in; }}
  body {{ font-family: -apple-system, Segoe UI, sans-serif; color: #222; margin: 0; padding: 24px; }}
  h1 {{ margin: 0 0 6px 0; font-size: 22pt; }}
  .meta {{ color: #555; font-size: 10pt; margin-bottom: 16px; }}
  .score {{ font-size: 56pt; font-weight: 700; color: {color}; line-height: 1; }}
  .grade {{ font-size: 16pt; font-weight: 600; color: {color}; margin-bottom: 4px; }}
  .summary {{ display: flex; gap: 8px; margin: 16px 0; }}
  .summary .box {{ flex: 1; padding: 12px; text-align: center; color: white; border-radius: 4px; }}
  .summary .box .n {{ font-size: 22pt; font-weight: 700; display: block; }}
  .summary .box .l {{ font-size: 9pt; text-transform: uppercase; }}
  .box-critical {{ background: #c0392b; }}
  .box-high     {{ background: #d35400; }}
  .box-medium   {{ background: #c47700; }}
  .box-low      {{ background: #7f8c8d; }}
  .box-info     {{ background: #2c3e50; }}
  h2 {{ font-size: 12pt; margin-top: 20px; border-bottom: 1px solid #bdc3c7; padding-bottom: 2px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10pt; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #34495e; color: white; }}
  .sev {{ font-weight: 700; width: 90px; }}
  .sev-critical {{ color: #c0392b; }} .sev-high {{ color: #d35400; }} .sev-medium {{ color: #c47700; }}
  .footnote {{ font-size: 9pt; color: #555; margin-top: 28px; font-style: italic; }}
  @media print {{ .noprint {{ display: none; }} }}
  .noprint {{ background: #fffde7; border: 1px solid #fdd835; padding: 8px; margin-bottom: 12px; font-size: 9pt; }}
</style>
</head><body>
<div class="noprint">Tip: open this file in your browser and choose <b>Print → Save as PDF</b>.
For a true PDF export, install reportlab (<code>pip install reportlab</code>) and re-run.</div>
<h1>WPSecScan Executive Summary</h1>
<div class="meta"><b>Target:</b> {_html.escape(report.target)} &nbsp;·&nbsp;
<b>Scanned:</b> {_html.escape(report.scanned_at)}</div>

<div class="score">{score}/100</div>
<div class="grade">Grade {risk_grade(score)} — {risk_label(score)}</div>

<div class="summary">
  <div class="box box-critical"><span class="n">{s.get('critical', 0)}</span><span class="l">Critical</span></div>
  <div class="box box-high"><span class="n">{s.get('high', 0)}</span><span class="l">High</span></div>
  <div class="box box-medium"><span class="n">{s.get('medium', 0)}</span><span class="l">Medium</span></div>
  <div class="box box-low"><span class="n">{s.get('low', 0)}</span><span class="l">Low</span></div>
  <div class="box box-info"><span class="n">{s.get('info', 0)}</span><span class="l">Info</span></div>
</div>

<h2>Top issues</h2>
<table><tr><th>Severity</th><th>Issue</th></tr>{top_rows}</table>

<h2>What to do next</h2>
<p>{_html.escape(next_text)}</p>

<div class="footnote">Generated by WPSecScan. Open the full HTML report for per-finding evidence
and remediation guidance.</div>
</body></html>
"""
    path.write_text(doc, encoding="utf-8")


def write(report: ScanReport, path: Path) -> None:
    """Write executive PDF. If reportlab is installed, produce a true PDF;
    otherwise write a print-friendly HTML page next to it."""
    if _has_reportlab():
        _render_pdf_reportlab(report, path)
        try:
            from .. import activity as _act
            _act.emit("reporter", f"Executive PDF: {path.name}")
        except (ImportError, OSError):
            pass
        return
    # Fall back to HTML. Always rewrite to .html so the file is openable
    # by extension regardless of what the caller passed (e.g. `Path("out")`
    # with no suffix would otherwise get HTML content under a bare filename).
    html_path = path.with_suffix(".html")
    _render_pdf_html_fallback(report, html_path)
    try:
        from .. import activity as _act
        _act.emit("reporter", f"Executive PDF (HTML fallback): {html_path.name}")
    except (ImportError, OSError):
        pass
