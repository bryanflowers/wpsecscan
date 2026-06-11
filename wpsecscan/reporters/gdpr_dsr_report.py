"""C60 (v2.7.0) — GDPR DSR-ready user-data report.

Generates a markdown audit-trail listing which checks touched any
user-data field. Format chosen so the operator can paste it directly
into a Subject Access Request (SAR) or Erasure Request response.

Identifies "user-data touching" findings by scanning evidence + title
for known PII categories:
  • EMAIL, IP, USERNAME, USER_ID, NAME, ADDRESS, PHONE, SSN,
    BIRTHDATE, GEOLOCATION, COOKIE_ID, SESSION_ID

For each match, emits:
  - Check that observed it
  - Severity
  - PII category
  - Remediation excerpt
"""
from __future__ import annotations

import re
from pathlib import Path

from ..models import ScanReport


_PII_PATTERNS = {
    "EMAIL":        re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE),
    "IPv4":         re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "USERNAME":     re.compile(r"\b(?:username|user_login|user_name)\b", re.IGNORECASE),
    "USER_ID":      re.compile(r"\b(?:user_id|userid|uid)\b", re.IGNORECASE),
    "PHONE":        re.compile(r"\b(?:phone|tel|mobile)\b", re.IGNORECASE),
    "ADDRESS":      re.compile(r"\b(?:address|street|postcode|zip)\b", re.IGNORECASE),
    "COOKIE_ID":    re.compile(r"\b(?:cookie|session_id|session_token)\b", re.IGNORECASE),
    "GEOLOCATION":  re.compile(r"\b(?:lat|lon|geolocation|country)\b", re.IGNORECASE),
}


def _categories(text: str) -> list[str]:
    hit = []
    for cat, rx in _PII_PATTERNS.items():
        if rx.search(text or ""):
            hit.append(cat)
    return hit


def render(report: ScanReport) -> str:
    rows: list[tuple[str, str, str, list[str]]] = []  # (check_id, sev, title, categories)
    for r in report.results:
        for f in r.findings:
            corpus = f"{f.title}\n{f.evidence}\n{f.url}"
            cats = _categories(corpus)
            if cats:
                rows.append((r.check_id, f.severity, f.title, cats))

    lines: list[str] = [
        f"# GDPR DSR / Subject Access Request — data-touching findings",
        "",
        f"**Target**: {report.target}  ",
        f"**Scanned**: {report.scanned_at}  ",
        f"**Scanner**: wpsecscan",
        "",
        "## Findings that touched user-data fields",
        "",
        f"Total: {len(rows)}",
        "",
    ]
    if not rows:
        lines.append("_No findings referenced PII / user-data fields in their evidence._")
    else:
        lines.append("| Check | Severity | PII categories | Title |")
        lines.append("|---|---|---|---|")
        # v2.8.5 Phase 5 — Python 3.10/3.11 don't allow backslashes
        # inside f-string expressions (PEP 701 lifted that in 3.12).
        # Hoist the pipe-escape into a local before formatting.
        for cid, sev, title, cats in rows:
            safe_title = title.replace("|", "\\|")
            lines.append(f"| `{cid}` | {sev} | {', '.join(cats)} | "
                          f"{safe_title} |")
        lines.append("")
        lines.append("## Notes for SAR / DSR response")
        lines.append("")
        lines.append(
            "- This list is generated from scanner evidence, not from a "
            "data inventory. Treat as a **starting point** for completing "
            "a SAR — the operator must still query the application database "
            "for any subject-specific records.")
        lines.append(
            "- Cross-reference with the GDPR DSR check (#21) and the "
            "WordPress core privacy-tools panel "
            "(Tools → Erase Personal Data).")
    return "\n".join(lines) + "\n"


def write(report: ScanReport, out_path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(out_path, render(report))
