"""ELI5 (Explain Like I'm 5) plain-English summary mode.

Round-64 #94 — produces a non-technical summary of a scan suitable for
showing to non-engineer stakeholders. No CVE numbers, no curl commands,
no remediation jargon — just "your site has these problems, in this
order of urgency".
"""
from __future__ import annotations


_SEVERITY_DESCRIPTIONS = {
    "critical": "extremely urgent — fix today",
    "high":     "urgent — fix this week",
    "medium":   "important — fix this month",
    "low":      "nice to fix — schedule it in",
    "info":     "informational — no action needed",
}

_TITLE_REWRITES = (
    # (substring to look for, plain-English replacement)
    ("SQL injection", "Someone can read or change your database without permission"),
    ("XSS", "Someone can inject code that runs in your visitors' browsers"),
    ("SSRF", "Someone can make your server fetch things on their behalf"),
    ("CSRF", "Someone can trick a logged-in user into doing things"),
    ("RCE", "Someone can run code on your server"),
    ("LFI", "Someone can read files on your server"),
    ("path traversal", "Someone can read files outside the public area"),
    ("open redirect", "Your site can be tricked into sending visitors to attacker sites"),
    ("CORS", "Other websites can read data from yours that they shouldn't"),
    ("HTTP method", "Some unusual web commands work that shouldn't"),
    ("info leak", "Your site reveals technical info that should be private"),
    ("debug", "Developer-only info is visible on the live site"),
    ("backup", "A site backup is publicly downloadable"),
    ("exposed file", "A file that should be private is publicly visible"),
    ("no MFA", "Important accounts don't have two-factor login enabled"),
    ("TLS", "Your site's encryption setup has weaknesses"),
    ("certificate", "Your site's SSL certificate has issues"),
    ("CVE", "A known security flaw exists in your software"),
)


def _rewrite_title(title: str) -> str:
    lower = title.lower()
    for needle, repl in _TITLE_REWRITES:
        if needle.lower() in lower:
            return repl
    return title  # no rewrite found — keep original


def render_eli5(report: dict | object) -> str:
    """Take a report dict (or ScanReport-like obj) and produce plain-English text."""
    if hasattr(report, "to_dict"):
        report = report.to_dict()
    findings = []
    for r in report.get("results", []):
        findings.extend(r.get("findings", []))

    if not findings:
        return (
            "Good news: WPSecScan didn't find anything urgent on your site today.\n"
            "Keep WordPress + plugins + themes up to date, and run another scan in 30 days."
        )

    # Group by severity
    by_sev = {sev: [] for sev in _SEVERITY_DESCRIPTIONS}
    for f in findings:
        sev = f.get("severity", "info")
        by_sev.setdefault(sev, []).append(f)

    lines = [f"Scan of {report.get('target', 'your site')}", ""]
    for sev in ("critical", "high", "medium", "low", "info"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        lines.append(f"{sev.upper()} ({_SEVERITY_DESCRIPTIONS[sev]}):")
        # De-dupe titles
        seen: set[str] = set()
        for f in items:
            t = _rewrite_title(f.get("title", "Unnamed issue"))
            if t in seen:
                continue
            seen.add(t)
            lines.append(f"  - {t}")
        lines.append("")

    lines.append("Next steps: forward this list to your web developer or hosting support. They'll know how to fix each one.")
    return "\n".join(lines)
