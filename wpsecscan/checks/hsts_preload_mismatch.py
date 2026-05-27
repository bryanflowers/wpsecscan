"""A30 (v2.6.0) — HSTS preload-list status mismatch.

A site claims `preload` in its Strict-Transport-Security header but
isn't on the actual Chrome preload list (or vice-versa). The mismatch
matters because:

  • `preload` in the header without listing = false sense of security
    (browsers won't preload until submission is accepted).
  • Listed without the header = removal is hard (operators sometimes
    forget they submitted years ago).

We use the freely-mirrored hstspreload.org JSON API.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    apex = urlparse(client.base_url).hostname or ""
    if not apex:
        return findings

    step("HSTS header inspect")
    r = await client.get("/")
    if r is None:
        return findings
    hsts = r.headers.get("strict-transport-security", "").lower()
    claims_preload = "preload" in hsts

    step(f"HSTS preload-list lookup for {apex}")
    listed = None
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8.0) as ext:
            api = await ext.get(f"https://hstspreload.org/api/v2/status?domain={apex}")
            if api.status_code == 200:
                data = api.json()
                listed = data.get("status") in ("preloaded", "pending")
    except Exception:  # noqa: BLE001
        return findings  # API down, skip

    if listed is None:
        return findings

    if claims_preload and not listed:
        findings.append(Finding(
            severity="low",
            title="HSTS header claims preload but apex isn't on the Chrome preload list",
            evidence=(
                f"HSTS header: {hsts}\n"
                f"hstspreload.org status for {apex}: not listed.\n"
                "Browsers don't preload until the site is accepted into the "
                "list — your header advertises a guarantee you don't yet have."
            ),
            remediation=(
                f"Submit at https://hstspreload.org/?domain={apex} after\n"
                "verifying the eligibility criteria (max-age >= 31536000,\n"
                "includeSubDomains, preload directive — which you have)."
            ),
            url=str(client.base_url),
            extra={"hsts": hsts, "preload_listed": listed},
        ))
    elif not claims_preload and listed:
        findings.append(Finding(
            severity="low",
            title="Apex is on HSTS preload list but header dropped the 'preload' directive",
            evidence=(
                f"HSTS header: {hsts!r}\n"
                f"hstspreload.org status for {apex}: listed.\n"
                "Removing the header doesn't remove the apex from the\n"
                "preload list; you must submit a removal request."
            ),
            remediation=(
                f"Either re-add 'preload' to the HSTS header, or submit a\n"
                f"removal at https://hstspreload.org/removal/?domain={apex}\n"
                "and wait ~12 months for the next Chrome list update."
            ),
            url=str(client.base_url),
            extra={"hsts": hsts, "preload_listed": listed},
        ))
    return findings
