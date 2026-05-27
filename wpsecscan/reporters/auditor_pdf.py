"""Item #50 — full-evidence "auditor" PDF.

The existing exec_pdf reporter writes a one-page summary suitable for
the C-suite. This auditor variant goes the other direction: for every
finding, include the raw evidence + remediation + URL + extra metadata
so the document is usable as legal / contractual evidence of what the
scanner saw at scan-time.

Uses reportlab when installed (true PDF). Falls back to a print-styled
HTML document otherwise — same fallback pattern as exec_pdf.
"""
from __future__ import annotations

import html as _html
from pathlib import Path

from ..models import ScanReport


def _has_reportlab() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def write(report: ScanReport, path: Path) -> None:
    if _has_reportlab():
        _render_pdf_reportlab(report, path)
    else:
        _render_html_fallback(report, path.with_suffix(".html"))


def _render_pdf_reportlab(report: ScanReport, path: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT

    styles = getSampleStyleSheet()
    title_s = ParagraphStyle("title", parent=styles["Title"], fontSize=20, alignment=TA_LEFT, spaceAfter=4)
    h1_s = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=14, spaceBefore=12, spaceAfter=6)
    h2_s = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=8, spaceAfter=4)
    body_s = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, spaceAfter=4, leading=12)
    code_s = ParagraphStyle("code", parent=styles["Code"], fontSize=8, leading=10, leftIndent=10)
    sev_s = {
        "critical": ParagraphStyle("sev-c", parent=body_s, textColor=HexColor("#c0392b"), fontName="Helvetica-Bold"),
        "high":     ParagraphStyle("sev-h", parent=body_s, textColor=HexColor("#d35400"), fontName="Helvetica-Bold"),
        "medium":   ParagraphStyle("sev-m", parent=body_s, textColor=HexColor("#c47700"), fontName="Helvetica-Bold"),
        "low":      ParagraphStyle("sev-l", parent=body_s, textColor=HexColor("#7f8c8d"), fontName="Helvetica-Bold"),
        "info":     ParagraphStyle("sev-i", parent=body_s, textColor=HexColor("#2c3e50"), fontName="Helvetica-Bold"),
    }

    # C52 — PDF/UA-friendly metadata. reportlab's "tagged" PDF support is
    # limited; we set the document title/author/lang/subject so screen
    # readers expose a proper title + language, and use SimpleDocTemplate's
    # title= which writes /Title in the PDF /Info dict. Full PDF/UA
    # structure tree is reportlab >= 4.x territory and noted in
    # docs/accessibility.md as a follow-up.
    doc = SimpleDocTemplate(
        str(path), pagesize=letter,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        title=f"WPSecScan Auditor Report — {report.target}",
        author="WPSecScan",
        subject=f"Security audit, score {report.risk_score}/100, scanned {report.scanned_at}",
        lang="en",
    )
    flow: list = []
    flow.append(Paragraph("WPSecScan Auditor Report", title_s))
    flow.append(Paragraph(f"<b>Target:</b> {_html.escape(report.target)}", body_s))
    flow.append(Paragraph(f"<b>Scanned:</b> {_html.escape(report.scanned_at)}", body_s))
    flow.append(Paragraph(
        f"<b>Risk score:</b> {report.risk_score}/100 · "
        f"<b>Total findings:</b> {len(report.all_findings)}",
        body_s,
    ))
    flow.append(Spacer(1, 0.15 * inch))

    flow.append(Paragraph("Severity counts", h1_s))
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
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#bdc3c7")),
    ]))
    flow.append(counts_table)
    flow.append(Spacer(1, 0.2 * inch))

    # Per-check section with EVERY finding's evidence + remediation +
    # extra fields. This is the legal-evidence pass — verbose by design.
    flow.append(Paragraph("Findings (full evidence)", h1_s))
    for r in report.results:
        if not r.findings:
            continue
        flow.append(Paragraph(_html.escape(r.check_name), h2_s))
        for f in r.findings:
            block: list = []
            sev_label = Paragraph(
                f"[{f.severity.upper()}] {_html.escape(f.title)}",
                sev_s.get(f.severity, body_s),
            )
            block.append(sev_label)
            if f.url:
                block.append(Paragraph(f"<b>URL:</b> {_html.escape(f.url)}", body_s))
            if f.evidence:
                block.append(Paragraph("<b>Evidence:</b>", body_s))
                # Preserve newlines + escape HTML; cap to keep individual
                # findings from blowing the page count.
                ev = _html.escape(f.evidence[:3000])
                if len(f.evidence) > 3000:
                    ev += "\n... [truncated for PDF; full evidence in JSON output]"
                block.append(Paragraph(ev.replace("\n", "<br/>"), code_s))
            if f.remediation:
                block.append(Paragraph("<b>Remediation:</b>", body_s))
                block.append(Paragraph(_html.escape(f.remediation[:2000]), body_s))
            if f.extra:
                # Surface known structured fields the operator may need
                # to cite (cve, owasp tag, etc.).
                extras_to_show = {
                    k: v for k, v in (f.extra or {}).items()
                    if k in ("cve", "cve_id", "owasp", "attack",
                              "fp_probability", "client_summary",
                              "ai_severity_score", "evidence_url")
                }
                if extras_to_show:
                    rows = [["Field", "Value"]]
                    for k, v in sorted(extras_to_show.items()):
                        rows.append([k, str(v)[:120]])
                    t = Table(rows, colWidths=[1.5 * inch, 5.0 * inch])
                    t.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#34495e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#bdc3c7")),
                    ]))
                    block.append(Spacer(1, 0.05 * inch))
                    block.append(t)
            block.append(Spacer(1, 0.15 * inch))
            # Keep each finding on the same page when possible.
            flow.append(KeepTogether(block))
        flow.append(Spacer(1, 0.1 * inch))

    flow.append(PageBreak())
    flow.append(Paragraph("Attestation", h1_s))
    flow.append(Paragraph(
        "This document is a record of WPSecScan's automated scan of the "
        "target above at the timestamp shown. Findings reflect the state "
        "of the target at scan-time. Evidence blobs are reproduced verbatim "
        "from the responses observed.",
        body_s,
    ))
    flow.append(Spacer(1, 0.2 * inch))
    flow.append(Paragraph("Auditor signature: _________________________________", body_s))
    flow.append(Spacer(1, 0.1 * inch))
    flow.append(Paragraph("Date:               _________________________________", body_s))
    flow.append(Spacer(1, 0.1 * inch))
    flow.append(Paragraph("<i>Generated by WPSecScan — see README.md for tool license + "
                            "authorisation requirements.</i>", body_s))

    doc.build(flow)


def _render_html_fallback(report: ScanReport, path: Path) -> None:
    """Print-styled HTML fallback when reportlab isn't installed.
    Identical layout to the PDF; the user prints to PDF via the browser."""
    s = report.summary
    rows_html: list[str] = []
    for r in report.results:
        if not r.findings:
            continue
        rows_html.append(f"<h3>{_html.escape(r.check_name)}</h3>")
        for f in r.findings:
            extras = ""
            if f.extra:
                show = {k: v for k, v in (f.extra or {}).items()
                        if k in ("cve", "cve_id", "owasp", "attack",
                                  "fp_probability", "client_summary",
                                  "ai_severity_score")}
                if show:
                    extras = "<table><tr><th>Field</th><th>Value</th></tr>" + "".join(
                        f"<tr><td>{_html.escape(k)}</td><td>{_html.escape(str(v))[:200]}</td></tr>"
                        for k, v in show.items()
                    ) + "</table>"
            ev = _html.escape((f.evidence or "")[:3000]).replace("\n", "<br>")
            rows_html.append(
                f"<div class='f sev-{f.severity}'>"
                f"<h4><span class='lbl'>[{f.severity.upper()}]</span> "
                f"{_html.escape(f.title)}</h4>"
                + (f"<p><b>URL:</b> {_html.escape(f.url)}</p>" if f.url else "")
                + (f"<p><b>Evidence:</b></p><pre>{ev}</pre>" if f.evidence else "")
                + (f"<p><b>Remediation:</b> {_html.escape(f.remediation)}</p>" if f.remediation else "")
                + extras
                + "</div>"
            )
    doc = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>WPSecScan Auditor Report — {_html.escape(report.target)}</title>
<style>
  @page {{ size: letter; margin: 0.6in; }}
  body {{ font-family: -apple-system, Segoe UI, sans-serif; color: #222; margin: 24px; }}
  h1 {{ font-size: 22pt; margin: 0 0 6px; }}
  h2 {{ font-size: 14pt; }}
  h3 {{ font-size: 12pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
  h4 {{ font-size: 11pt; margin: 6px 0; }}
  pre {{ background: #f4f4f4; border: 1px solid #ddd; padding: 8px; font: 9pt ui-monospace; white-space: pre-wrap; }}
  .lbl {{ font-weight: 700; }}
  .sev-critical .lbl {{ color: #c0392b; }} .sev-high .lbl {{ color: #d35400; }}
  .sev-medium .lbl {{ color: #c47700; }} .sev-low .lbl {{ color: #7f8c8d; }}
  table {{ border-collapse: collapse; width: 100%; margin: 6px 0; font-size: 9pt; }}
  th, td {{ border: 1px solid #ddd; padding: 4px 6px; }}
  th {{ background: #34495e; color: #fff; }}
  .f {{ break-inside: avoid; page-break-inside: avoid; margin-bottom: 12pt; }}
  .summary {{ display: flex; gap: 8px; }}
  .summary .box {{ flex: 1; padding: 10px; text-align: center; color: #fff; border-radius: 4px; }}
  .box-critical {{ background: #c0392b; }} .box-high {{ background: #d35400; }}
  .box-medium {{ background: #c47700; }} .box-low {{ background: #7f8c8d; }}
  .box-info {{ background: #2c3e50; }}
  .noprint {{ background: #fffde7; border: 1px solid #fdd835; padding: 8px; margin-bottom: 12px; font-size: 9pt; }}
  @media print {{ .noprint {{ display: none; }} }}
</style>
</head><body>
<div class="noprint">Tip: open in browser and <b>Print → Save as PDF</b>. For a true PDF, install reportlab (<code>pip install wpsecscan[pdf]</code>).</div>
<h1>WPSecScan Auditor Report</h1>
<p><b>Target:</b> {_html.escape(report.target)}<br>
<b>Scanned:</b> {_html.escape(report.scanned_at)}<br>
<b>Risk score:</b> {report.risk_score}/100 · <b>Findings:</b> {len(report.all_findings)}</p>
<h2>Severity counts</h2>
<div class="summary">
  <div class="box box-critical">Critical<br><b>{s.get('critical',0)}</b></div>
  <div class="box box-high">High<br><b>{s.get('high',0)}</b></div>
  <div class="box box-medium">Medium<br><b>{s.get('medium',0)}</b></div>
  <div class="box box-low">Low<br><b>{s.get('low',0)}</b></div>
  <div class="box box-info">Info<br><b>{s.get('info',0)}</b></div>
</div>
<h2>Findings (full evidence)</h2>
{''.join(rows_html)}
<h2 style="page-break-before:always">Attestation</h2>
<p>This document is a record of WPSecScan's automated scan of the target above
at the timestamp shown. Findings reflect the state of the target at scan-time.
Evidence blobs are reproduced verbatim from the responses observed.</p>
<p>Auditor signature: ______________________________________________</p>
<p>Date:               ______________________________________________</p>
</body></html>
"""
    path.write_text(doc, encoding="utf-8")
