"""O141 (v2.6.0) — Speculation Rules audit.

WP 6.8 includes the official Speculation-Rules API support: pages
emit `<script type="speculationrules">` declaring which URLs the
browser should prerender/prefetch. Misconfigured rules expose:

  • Admin-only URLs (wp-admin/...) being prerendered for anonymous
    visitors → server-side render cost + potential XSRF surface.
  • External URLs in the prerender list → CSP / network-policy leak.
  • Too-aggressive `eagerness: immediate` causing crawl-loops.

Passive: extract every speculationrules script + parse JSON; flag
medium per problematic rule found.
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding


_BLOCK_RE = re.compile(
    r'<script\s[^>]*type\s*=\s*["\']speculationrules["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("speculationrules: GET /")
    home = await client.get("/")
    if home is None or not home.text:
        return findings

    issues: list[str] = []
    for m in _BLOCK_RE.finditer(home.text):
        try:
            rules = json.loads(m.group(1).strip())
        except (ValueError, AttributeError):
            continue
        for action_type in ("prerender", "prefetch"):
            for entry in rules.get(action_type, []) or []:
                if not isinstance(entry, dict):
                    continue
                urls = entry.get("urls", [])
                if isinstance(urls, list):
                    for u in urls:
                        if isinstance(u, str):
                            if "/wp-admin/" in u or "/wp-json/" in u:
                                issues.append(f"{action_type} → admin URL: {u}")
                            if u.startswith(("http://", "https://")) and "example.com" not in u:
                                issues.append(f"{action_type} → cross-origin: {u}")
                eagerness = entry.get("eagerness", "")
                if eagerness == "immediate":
                    issues.append(f"{action_type}: 'immediate' eagerness on a public page can trigger crawl-loops")

    if issues:
        findings.append(Finding(
            severity="medium",
            title=f"Speculation Rules expose problematic URLs ({len(issues)} issue(s))",
            evidence="Speculation-rules issues:\n  " + "\n  ".join(issues[:20]),
            remediation=(
                "1. Remove admin URLs from prerender/prefetch lists.\n"
                "2. Restrict cross-origin URLs to a verified allow-list.\n"
                "3. Switch 'immediate' → 'moderate' or 'conservative' on\n"
                "   public pages to avoid crawl-loop / bandwidth abuse."
            ),
            url=client.url("/"),
            extra={"issues": issues[:20]},
        ))
    return findings
