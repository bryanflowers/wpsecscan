from __future__ import annotations

# #14: Rich is the preferred console renderer but it's not part of the standard
# library. If it isn't installed, fall back to a plain-text renderer below so
# the CLI still works (degraded experience, but no crash).
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    Console = None  # type: ignore[assignment]
    Panel = None    # type: ignore[assignment]
    Table = None    # type: ignore[assignment]
    Text = None     # type: ignore[assignment]

from .. import confidence as _confidence
from .. import playbook as _playbook
from .. import tags as _tags
from ..models import ScanReport

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _render_plain(report: ScanReport) -> None:
    """Plain-text fallback when Rich isn't available."""
    line = "=" * 72
    print(line)
    print(f"WPSecScan  {report.target}")
    print(f"Scanned at {report.scanned_at}  duration {report.duration_ms} ms")
    print(line)
    for r in report.results:
        if r.error:
            print(f"\n[{r.check_name}]  ERROR: {r.error}")
            continue
        if not r.findings:
            print(f"\n[{r.check_name}]  no findings  ({r.duration_ms} ms)")
            continue
        print(f"\n--- {r.check_name}  ({len(r.findings)} finding(s), {r.duration_ms} ms) ---")
        for f in r.findings:
            print(f"  [{f.severity.upper():>8}] {f.title}")
            if f.evidence:
                for ev in (f.evidence or "").splitlines():
                    print(f"            {ev}")
            if f.remediation:
                print(f"      Fix: {f.remediation}")
    s = report.summary
    print("\n" + line)
    print(
        f"Summary:  {s.get('critical',0)} critical · {s.get('high',0)} high · "
        f"{s.get('medium',0)} medium · {s.get('low',0)} low · {s.get('info',0)} info"
    )
    from ..risk import risk_label, risk_grade
    print(f"Risk score: {report.risk_score}/100  (grade {risk_grade(report.risk_score)}, {risk_label(report.risk_score)})")
    print(line)


def render(report: ScanReport, console=None) -> None:
    if not _HAS_RICH:
        _render_plain(report)
        return
    console = console or Console()
    console.rule(f"[bold]WPSecScan[/bold]  {report.target}")
    console.print(f"[dim]Scanned at {report.scanned_at} • duration {report.duration_ms} ms[/dim]")

    # Executive summary at the TOP — a CI log tail or a quick glance shouldn't
    # have to scroll past every finding to learn the verdict.
    from ..risk import risk_grade, risk_label
    s = report.summary
    score = report.risk_score
    sev_parts = []
    for sev, color in (("critical", "red"), ("high", "red"), ("medium", "yellow"),
                       ("low", "cyan"), ("info", "dim")):
        n = s.get(sev, 0)
        if n:
            sev_parts.append(f"[{color}]{n} {sev}[/{color}]")
    sev_line = " · ".join(sev_parts) if sev_parts else "[green]no findings[/green]"
    grade = risk_grade(score)
    grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}.get(grade, "white")
    console.print(
        f"[bold]Risk: {score}/100[/bold]  ·  grade [{grade_color}]{grade}[/{grade_color}]  ·  "
        f"{sev_line}  ·  [dim]{risk_label(score)}[/dim]\n"
    )

    for r in report.results:
        if r.error:
            console.print(
                Panel(
                    f"[red]{r.error}[/red]",
                    title=f"{r.check_name} [dim]({r.duration_ms} ms)[/dim]",
                    border_style="red",
                )
            )
            continue
        if not r.findings:
            console.print(f"[dim]✓ {r.check_name} — no findings ({r.duration_ms} ms)[/dim]")
            continue

        chip = _tags.short_chip(r.check_id)
        chip_str = f" [magenta]{chip}[/magenta]" if chip else ""
        table = Table(
            title=f"{r.check_name}{chip_str} [dim]({r.duration_ms} ms)[/dim]",
            show_lines=True,
            title_justify="left",
            header_style="bold",
        )
        table.add_column("Sev", width=9)
        table.add_column("Finding", overflow="fold")
        table.add_column("Evidence / remediation", overflow="fold")
        # Detect WAF from the global report context (downgrades confidence)
        waf_detected = any(
            "WAF" in (x.title or "") or "CDN detected" in (x.title or "")
            for res in report.results if res.check_id == "waf"
            for x in res.findings
        )
        for f in r.findings:
            sev = Text(f.severity.upper(), style=SEVERITY_STYLE.get(f.severity, ""))
            conf = _confidence.compute_confidence(f, r.check_id, waf_detected=waf_detected)
            conf_style = {"high": "bold green", "medium": "yellow", "low": "dim"}[conf]
            title_text = f"{f.title}\n[{conf_style}]{_confidence.chip(conf)}[/{conf_style}]"
            # B11 (v2.8.0) — `f.evidence` may be None; the `+=` on the
            # next line raised TypeError when a finding had remediation
            # but no evidence. Coerce to empty string first.
            details = f.evidence or ""
            if f.remediation:
                details += f"\n\n[bold]Fix:[/bold] {f.remediation}"
            table.add_row(sev, title_text, details)
        console.print(table)

        # Append condensed exploit playbook beneath the table — one block per check,
        # not per finding, so we don't repeat the same sqlmap/metasploit lines 10 times.
        pb_raw = _playbook.get_playbook(r.check_id)
        if pb_raw:
            pb = _playbook.substitute(pb_raw, report.target)
            buckets = _playbook.ordered_buckets(pb)
            if buckets:
                pb_lines: list[str] = []
                for field, label, content in buckets:
                    if field == "how_an_attacker_uses_this":
                        pb_lines.append(f"[bold]{label}:[/bold] {content}")
                    elif field == "references":
                        for line in content[:3]:
                            pb_lines.append(f"  [dim]ref:[/dim] {line}")
                    else:
                        pb_lines.append(f"[bold]{label}[/bold]")
                        for line in content[:2]:  # first 2 per bucket in console; full set in HTML/GUI
                            pb_lines.append(f"  {line}")
                console.print(Panel("\n".join(pb_lines), title="[bold cyan]Exploit playbook[/bold cyan]", border_style="cyan", title_align="left"))

    from ..risk import risk_tier, risk_label, risk_grade
    s = report.summary
    score = report.risk_score
    tier = risk_tier(score)
    tier_color = {"green": "bold green", "yellow": "bold yellow",
                  "orange": "bold orange3", "red": "bold red"}[tier]
    line = (
        f"[bold]Summary:[/bold]  "
        f"[bold white on red] {s['critical']} critical [/bold white on red]  "
        f"[bold red]{s['high']} high[/bold red]  "
        f"[yellow]{s['medium']} medium[/yellow]  "
        f"[cyan]{s['low']} low[/cyan]  "
        f"[dim]{s['info']} info[/dim]\n"
        f"[bold]Risk score:[/bold]  [{tier_color}]{score}/100  · grade {risk_grade(score)}  · ({risk_label(score)})[/{tier_color}]"
    )
    console.print()
    console.print(Panel(line, border_style="white"))

    # Round-56: "What ran" panel — itemise every feature category that fired.
    try:
        _render_what_ran(report, console)
    except Exception:  # noqa: BLE001
        # Stats panel is decorative — never block the scan summary on a render bug.
        pass


def _render_what_ran(report: ScanReport, console) -> None:
    """Append a 'What ran' panel showing per-category activity counts pulled
    from the activity bus, plus check inventory + slow-check warnings."""
    from .. import activity as _act
    counts = _act.counts_by_category()
    if not counts and not report.results:
        return  # nothing to show

    # Inventory totals
    total_checks = len(report.results)
    ran = sum(1 for r in report.results if not r.error)
    incremental_skipped = sum(
        1 for r in report.results if r.error and "incremental" in (r.error or "").lower()
    )
    auto_disabled = sum(
        1 for r in report.results if r.error and "auto-disabled" in (r.error or "").lower()
    )
    waf_skipped = sum(
        1 for r in report.results if r.error and "waf" in (r.error or "").lower()
    )

    lines: list[str] = []
    inv = (f"{total_checks} checks selected · {ran} ran"
           f"{' · ' + str(incremental_skipped) + ' skipped (incremental)' if incremental_skipped else ''}"
           f"{' · ' + str(waf_skipped) + ' WAF-blocked' if waf_skipped else ''}"
           f"{' · ' + str(auto_disabled) + ' auto-disabled' if auto_disabled else ''}")
    lines.append(inv)
    lines.append(f"duration {report.duration_ms / 1000:.1f}s")
    lines.append("")

    def _summarise_cat(cat: str, label: str, color: str) -> str | None:
        events = _act.events_by_category(cat)
        if not events:
            return None
        # Show the last 4 messages or so, truncated
        last = [e.get("message", "")[:60] for e in events[-4:]]
        return f"  [{color}]{label:12}[/{color}] {len(events)} event(s) · " + " · ".join(last)

    for cat, label, color in (
        ("threat_intel", "threat-intel", "yellow"),
        ("reporter",     "reporter",     "blue"),
        ("artifact",     "artifact",     "green"),
        ("integration",  "integration",  "magenta"),
        ("governance",   "governance",   "cyan"),
        ("meta",         "meta",         "yellow"),
    ):
        out = _summarise_cat(cat, label, color)
        if out:
            lines.append(out)

    # Slow-check budget warnings
    try:
        from .. import check_health as _ch
        warnings = _ch.budget_warnings(report.results)
        if warnings:
            lines.append("")
            lines.append("  [red]slow checks[/red] (rolling 20-scan median × 5 threshold):")
            for w in warnings[:3]:
                lines.append(f"    - {w}")
    except ImportError:
        pass

    console.print()
    console.print(Panel("\n".join(lines), title="What ran", border_style="dim",
                        title_align="left"))


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def exit_code(report: ScanReport, fail_on: str | None = None) -> int:
    """Compute the CLI exit code.

    Default: 0 = clean/info-only, 1 = medium issues, 2 = critical/high issues.

    D5: `fail_on` overrides the default. Accepts a single severity name or a
    comma-separated list (e.g. "critical", "high,critical", "medium"). Returns
    2 if ANY finding at/above that severity exists, else 0.
    """
    s = report.summary
    if fail_on:
        thresholds = [t.strip().lower() for t in fail_on.split(",") if t.strip()]
        # Lowest-rank threshold wins (any finding ≥ this severity fails).
        ranks = [_SEVERITY_RANK[t] for t in thresholds if t in _SEVERITY_RANK]
        if not ranks:
            # Fall through to default if user passed garbage.
            pass
        else:
            min_rank = min(ranks)
            for sev, count in s.items():
                if count and _SEVERITY_RANK.get(sev, -1) >= min_rank:
                    return 2
            return 0
    if s.get("critical", 0) or s.get("high", 0):
        return 2
    if s.get("medium", 0):
        return 1
    return 0
