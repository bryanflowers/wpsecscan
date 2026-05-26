"""Audit the `Link:` response header for internal URLs.

The `Link:` header on a WordPress front-page typically contains:
  - rel="https://api.w.org/" pointing at the REST API base
  - rel="next" / rel="prev" pointing at adjacent pages
  - rel="shortlink" / rel="canonical"

Reverse-proxy misconfigurations can leak internal/staging URLs in these
links (e.g. `https://staging-internal.dev/...` appearing on a production
site because the canonical URL is computed from `$_SERVER['HTTP_HOST']`
before the reverse proxy rewrites it). This check fires when any Link
relation points at a hostname that doesn't match the scan target.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


_LINK_RE = re.compile(r"<([^>]+)>\s*;\s*rel=[\"']?([a-zA-Z0-9._:/\-]+)", re.IGNORECASE)


_SUSPECT_TOKENS = ("staging", "stage", "dev", "test", "localhost",
                   "internal", "intranet", "127.0.0.1", "0.0.0.0",
                   ".local", ".lan", ".corp")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("checking Link: header on /...")
    r = await client.get("/")
    if r is None:
        return findings
    link_val = r.headers.get("Link") or r.headers.get("link") or ""
    if not link_val:
        return findings
    target_host = (urlparse(ctx["target"]).hostname or "").lower()
    suspicious: list[tuple[str, str]] = []  # (url, rel)
    for m in _LINK_RE.finditer(link_val):
        link_url = m.group(1).strip()
        rel = m.group(2).strip()
        link_host = (urlparse(link_url).hostname or "").lower()
        if not link_host:
            continue
        if link_host == target_host:
            continue
        # Different host — check for suspect tokens.
        if any(tok in link_host for tok in _SUSPECT_TOKENS):
            suspicious.append((link_url, rel))
    if suspicious:
        lines = "\n".join(f"  rel={rel!r}: {url}" for url, rel in suspicious)
        findings.append(Finding(
            severity="medium",
            title=f"Link: header on / leaks {len(suspicious)} internal-looking URL(s)",
            evidence=(
                f"The Link response header points at hostnames containing internal/staging tokens:\n{lines}\n\n"
                "This usually means the canonical / API-root URLs are being computed "
                "from the un-rewritten internal hostname rather than the public host. "
                "It leaks infrastructure topology and may indicate a misconfigured "
                "reverse proxy."
            ),
            remediation=(
                "Set `WP_HOME` and `WP_SITEURL` to the public URL explicitly in "
                "wp-config.php so canonical/REST URLs don't fall back to "
                "$_SERVER['HTTP_HOST']. Also audit any plugins that override the "
                "Link header generation."
            ),
            url=ctx["target"],
        ))
    return findings
