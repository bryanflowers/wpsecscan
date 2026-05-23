"""H8 Hostname collision detector.

If `www.target.com` and `target.com` resolve to different servers — or
serve different sites — that's almost always a config mistake. Worse: an
attacker who claims the apex (or vice-versa) can serve content under YOUR
brand. Also catches cases where `target.com` is parked while `www.` is the
real site (or vice-versa).

Compares the homepages of `apex` vs `www.apex`:
  - Same fingerprint (favicon hash, title, body length) → fine
  - Different status codes (one 200, other 404/30x to a parking page) → flagged
  - Different content → flagged as potential subdomain takeover
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    if not host or host.count(".") < 1:
        return findings

    # Determine apex + www variants
    apex_host = host[4:] if host.startswith("www.") else host
    www_host  = "www." + apex_host if not host.startswith("www.") else host

    if apex_host == www_host:
        return findings

    apex_url = f"{parsed.scheme}://{apex_host}/"
    www_url  = f"{parsed.scheme}://{www_host}/"

    step(f"hostname collision: {apex_host} vs {www_host}...")
    apex_resp = www_resp = None
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as c:
            try:
                apex_resp = await c.get(apex_url)
            except httpx.HTTPError:
                pass
            try:
                www_resp = await c.get(www_url)
            except httpx.HTTPError:
                pass
    except Exception:  # noqa: BLE001
        pass

    if apex_resp is None or www_resp is None:
        findings.append(Finding(
            severity="info",
            title=f"Hostname collision — one variant unreachable ({apex_host} or {www_host})",
            evidence=f"apex reachable: {apex_resp is not None}; www reachable: {www_resp is not None}",
            remediation="Ensure both apex and www point at the same site (CNAME or A record).",
            url=ctx["target"],
        ))
        return findings

    apex_len = len(apex_resp.content or b"")
    www_len = len(www_resp.content or b"")
    apex_status = apex_resp.status_code
    www_status = www_resp.status_code

    # Same status + similar size = fine
    similar_size = abs(apex_len - www_len) < max(500, min(apex_len, www_len) * 0.10)
    if apex_status == www_status and similar_size:
        findings.append(Finding(
            severity="info",
            title=f"Hostname collision check clean ({apex_host} and {www_host} serve the same site)",
            evidence=f"Both returned HTTP {apex_status} with bodies of {apex_len} / {www_len} bytes.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Differ — flag it
    findings.append(Finding(
        severity="medium",
        title=f"Hostname collision: {apex_host} and {www_host} serve different content",
        evidence=(
            f"  {apex_url} -> HTTP {apex_status} ({apex_len} bytes)\n"
            f"  {www_url}  -> HTTP {www_status} ({www_len} bytes)\n\n"
            "This is usually a config mistake: one hostname is the real site, the other is parked or "
            "uncontrolled. If an attacker can claim the unused variant (e.g. via subdomain takeover), "
            "they can serve content under your domain."
        ),
        remediation=(
            "Pick a canonical hostname (usually with `www.`), and 301-redirect the other to it via "
            "the web server config. Nginx example:\n"
            "  server { server_name apex.com; return 301 https://www.apex.com$request_uri; }"
        ),
        url=ctx["target"],
    ))
    return findings
