"""A16 (v2.6.0) — Vercel / Netlify / GH-Pages preview-URL leak.

Headless WP setups deploy the frontend to Vercel/Netlify/GH-Pages and
publish preview URLs per branch. Those preview hosts often:

  • Skip the production WAF.
  • Skip authentication that the prod CDN enforces.
  • Expose draft posts / unpublished previews.

This check scrapes robots.txt, sitemap.xml, and the homepage HTML for
preview-URL patterns and flags any reference to a `*.vercel.app`,
`*.netlify.app`, `*.pages.dev`, `*.github.io`, `*.fly.dev`,
`*.surge.sh` host that isn't on the same apex as the target.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


_PREVIEW_HOST_RE = re.compile(
    r'https?://([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.'
    r'(?:vercel\.app|netlify\.app|pages\.dev|github\.io|fly\.dev|surge\.sh|render\.com))',
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    apex = urlparse(client.base_url).hostname or ""
    apex_root = ".".join(apex.lower().split(".")[-2:]) if apex else ""

    leaked: set[str] = set()
    for path in ("/", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        step(f"preview-URL scan: {path}")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for m in _PREVIEW_HOST_RE.finditer(r.text):
            host = m.group(1).lower()
            # Skip if the preview host is on the operator's own apex
            # (some teams host www.example.com on Vercel intentionally).
            if apex_root and apex_root in host:
                continue
            leaked.add(host)

    if leaked:
        findings.append(Finding(
            severity="medium",
            title=f"Frontend preview-URL hosts referenced: {len(leaked)} foreign hosts",
            evidence=(
                "Preview / staging hosts referenced from sitemap or HTML:\n  "
                + "\n  ".join(sorted(leaked)) + "\n\n"
                "These hosts likely bypass your production WAF and may serve "
                "unpublished drafts / staging content that wasn't intended "
                "to be public."
            ),
            remediation=(
                "1. For each host, confirm whether it should be public.\n"
                "2. If not, enable Vercel/Netlify password-protection on the "
                "preview deployment.\n"
                "3. Add a `<meta name='robots' content='noindex'>` to staging "
                "templates so the URLs don't appear in search results.\n"
                "4. Audit your sitemap-generator: it should NOT include the "
                "staging origin in robots.txt or sitemap.xml."
            ),
            url=client.url("/"),
            extra={"hosts": sorted(leaked)},
        ))
    return findings
