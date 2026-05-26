"""Markdown report renderer.

Same shape as the GUI's File → Export markdown action, but available from
the CLI as `--md`. Uses a 4-backtick fence for evidence so any user-supplied
text containing ``` doesn't break the fencing.
"""
from __future__ import annotations

from pathlib import Path

from ..models import ScanReport


def render(report: ScanReport) -> str:
    s = report.summary
    from ..risk import risk_grade, risk_label
    from .. import confidence as _conf
    score = report.risk_score
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )
    lines: list[str] = [
        f"# WPSecScan — {report.target}",
        "",
        f"- **Scanned**: {report.scanned_at}",
        f"- **Duration**: {report.duration_ms} ms",
        f"- **Risk score**: {score}/100  ·  grade **{risk_grade(score)}**  ·  {risk_label(score)}",
        f"- **Summary**: {s.get('critical', 0)} critical · {s.get('high', 0)} high · "
        f"{s.get('medium', 0)} medium · {s.get('low', 0)} low · {s.get('info', 0)} info",
        "",
        "---",
        "",
    ]
    for res in report.results:
        if res.error:
            lines.append(f"## ⚠ {res.check_name}\n\nError: `{res.error}`\n")
            continue
        if not res.findings:
            continue
        lines.append(f"## {res.check_name}")
        lines.append("")
        for f in res.findings:
            conf = _conf.compute_confidence(f, res.check_id, waf_detected=waf_detected)
            lines.append(f"### [{f.severity.upper()}] {f.title}  *({_conf.chip(conf)})*")
            lines.append("")
            if f.url:
                lines.append(f"- URL: {f.url}")
            if f.evidence:
                lines.append("")
                lines.append("**Evidence**")
                lines.append("")
                # 4-backtick fence — user-supplied content can contain ``` safely.
                lines.append("````")
                evidence = f.evidence if len(f.evidence) <= 4000 else f.evidence[:4000] + "\n... [truncated]"
                lines.append(evidence)
                lines.append("````")
            if f.remediation:
                lines.append("")
                lines.append("**Remediation**")
                lines.append("")
                lines.append(f.remediation)
            lines.append("")
    return "\n".join(lines)


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"Markdown: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
