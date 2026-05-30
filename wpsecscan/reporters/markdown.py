"""Markdown report renderer.

Same shape as the GUI's File → Export markdown action, but available from
the CLI as `--md`. Uses a 4-backtick fence for evidence so any user-supplied
text containing ``` doesn't break the fencing.
"""
from __future__ import annotations

from pathlib import Path

from ..models import ScanReport


def render(report: ScanReport, top_n: int | None = None) -> str:
    """Render the report as Markdown.

    Pass `top_n` to keep only the top-N findings by severity (useful for
    posting into Slack/Discord where 4000-character messages are the limit).
    Severity ordering is critical > high > medium > low > info; within a
    severity, scan-execution order is preserved.
    """
    s = report.summary
    from ..models import SEVERITY_RANK
    from ..risk import risk_grade, risk_label
    from .. import confidence as _conf
    score = report.risk_score
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )

    # Truncate to top-N when requested. Sort all (check, finding) pairs by
    # severity desc, keep the first N, then group back into per-check sections
    # so the existing rendering loop still produces clean output.
    if top_n is not None and top_n > 0:
        ranked: list[tuple[int, object, object]] = []
        for res in report.results:
            for f in res.findings:
                ranked.append((SEVERITY_RANK.get(f.severity, -1), res, f))
        ranked.sort(key=lambda t: t[0], reverse=True)
        keep_pairs = ranked[:top_n]
        from collections import defaultdict
        keep_per_res: dict = defaultdict(list)
        for _r, res, f in keep_pairs:
            keep_per_res[id(res)].append((res, f))
        # Build a filtered report.results-shaped list preserving original order
        from dataclasses import replace
        filtered: list = []
        for res in report.results:
            kept = [f for r, f in keep_per_res.get(id(res), []) if r is res]
            if kept:
                filtered.append(replace(res, findings=kept))
        # Mutate locally — we don't touch the caller's report object
        report = replace(report, results=filtered)
        s = report.summary
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
            client_summary = (f.extra or {}).get("client_summary")
            if client_summary:
                audience = (f.extra or {}).get("client_summary_audience", "client")
                lines.append("")
                lines.append(f"**Plain-English ({audience})**")
                lines.append("")
                lines.append(f"> {client_summary}")
            if f.evidence:
                lines.append("")
                lines.append("**Evidence**")
                lines.append("")
                # B40 (v2.8.0) — was: 3-backtick fence with ZWS hack
                # for embedded triple-backticks. The hack was fragile
                # across GFM renderers (some normalise ZWS away).
                # Switch to a 4-backtick fence (CommonMark spec
                # allows any backtick run >= 3 as a fence opener,
                # and the closer must match the opener's length).
                # Evidence containing literal "```" no longer needs
                # escaping. Slack still renders 3 OR 4 backticks as
                # code blocks.
                evidence = f.evidence if len(f.evidence) <= 4000 else f.evidence[:4000] + "\n... [truncated]"
                lines.append("````")
                lines.append(evidence)
                lines.append("````")
            if f.remediation:
                lines.append("")
                lines.append("**Remediation**")
                lines.append("")
                lines.append(f.remediation)
            lines.append("")
    return "\n".join(lines)


def write(report: ScanReport, path: Path, top_n: int | None = None) -> None:
    path.write_text(render(report, top_n=top_n), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"Markdown: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
