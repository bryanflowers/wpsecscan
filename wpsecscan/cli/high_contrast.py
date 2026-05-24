"""High-contrast CLI output.

Round-64 #101 — `--high-contrast` flag emits only bold/non-bold,
white/black, with no colour. Easier on users with low vision who use
terminals with custom palettes.
"""
from __future__ import annotations


# Only the two SGRs we need: bold on, all off.
BOLD = "\x1b[1m"
OFF = "\x1b[0m"


def render_finding(severity: str, title: str, url: str = "") -> str:
    """Severity in bold, rest plain."""
    sev_marker = f"{BOLD}[{severity.upper()}]{OFF}"
    if url:
        return f"{sev_marker} {title}\n         {url}"
    return f"{sev_marker} {title}"


def render_summary(summary: dict) -> str:
    total = sum(int(v) for v in summary.values())
    lines = [f"{BOLD}Summary:{OFF} {total} findings"]
    for sev in ("critical", "high", "medium", "low", "info"):
        n = int(summary.get(sev, 0))
        if n:
            lines.append(f"  {sev:8s} {n}")
    return "\n".join(lines)
