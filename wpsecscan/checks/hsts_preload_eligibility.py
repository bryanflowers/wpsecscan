"""HSTS preload eligibility audit.

For inclusion in the Chrome preload list (which Firefox/Safari also use),
the HSTS header must have:
  - max-age >= 31536000 (1 year)
  - includeSubDomains directive present
  - preload directive present
  - the apex domain must be served over HTTPS

Existing tls_headers.py just checks that HSTS exists. This audits the
three preload conditions and additionally hits hstspreload.org's status
API to confirm whether the domain is already on the list.
"""
from __future__ import annotations
import os
import re
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


async def _preload_status(domain: str) -> str | None:
    """Returns 'preloaded', 'pending', 'unknown', or None."""
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"https://hstspreload.org/api/v2/status?domain={domain}")
            if r.status_code != 200:
                return None
            data = r.json()
            if isinstance(data, dict):
                return data.get("status") or "unknown"
    except (httpx.HTTPError, OSError, ValueError):
        return None
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    parsed = urlparse(ctx["target"])
    if parsed.scheme != "https":
        return findings
    domain = parsed.hostname or ""
    r = await client.get("/")
    if r is None:
        return findings
    hsts = r.headers.get("Strict-Transport-Security") or r.headers.get("strict-transport-security") or ""
    if not hsts:
        return findings  # tls_headers handles "missing HSTS"
    # Parse
    m = _MAX_AGE_RE.search(hsts)
    max_age = int(m.group(1)) if m else 0
    has_subdomains = "includesubdomains" in hsts.lower()
    has_preload = "preload" in hsts.lower()
    eligible = (max_age >= 31_536_000) and has_subdomains and has_preload
    # Always check the preload list, even if not eligible — useful intel.
    step("querying hstspreload.org status...")
    status = await _preload_status(domain)
    if status == "preloaded":
        findings.append(Finding(
            severity="info",
            title=f"{domain} is on the Chrome HSTS preload list",
            evidence=f"hstspreload.org/api/v2/status reports: preloaded.\nHeader: {hsts[:120]}",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings
    if eligible:
        findings.append(Finding(
            severity="low",
            title="HSTS preload eligible but not yet submitted",
            evidence=(
                f"HSTS header satisfies all three preload conditions:\n"
                f"  max-age = {max_age} (>= 31536000 ✓)\n"
                f"  includeSubDomains ✓\n"
                f"  preload directive ✓\n"
                f"hstspreload.org status: {status or '(could not check)'}"
            ),
            remediation=(
                f"Submit {domain} at https://hstspreload.org/?domain={domain}. "
                "Inclusion is reviewed by the Chrome team and propagates with "
                "the next browser release. Once preloaded, the browser refuses "
                "HTTP for this domain even on first visit — defends against "
                "first-load SSL-strip attacks."
            ),
            url=f"https://hstspreload.org/?domain={domain}",
        ))
        return findings
    # Not eligible — explain what's missing
    missing: list[str] = []
    if max_age < 31_536_000:
        missing.append(f"max-age={max_age} (need ≥31536000 / 1 year)")
    if not has_subdomains:
        missing.append("includeSubDomains")
    if not has_preload:
        missing.append("preload directive")
    findings.append(Finding(
        severity="info",
        title="HSTS not preload-eligible — fix to qualify for the preload list",
        evidence=f"Missing preload conditions: {', '.join(missing)}.\nCurrent header: {hsts[:200]}",
        remediation=(
            "Update the HSTS header to:\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "Verify all subdomains are HTTPS-only first — preload is a one-way "
            f"door for the apex domain. Submit at hstspreload.org/?domain={domain} "
            "once eligible."
        ),
        url=ctx["target"],
    ))
    return findings
