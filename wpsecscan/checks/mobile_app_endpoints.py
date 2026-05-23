"""#38 — Mobile-app endpoint discovery check.

Wraps mobile_app_discovery.discover and reports any universal-link
endpoints + Android app packages found in the target's
`.well-known/apple-app-site-association` / `assetlinks.json` files.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    from .. import mobile_app_discovery as _mad
    step("checking app-site-association / assetlinks...")
    res = await _mad.discover(client)
    if not res["found_paths"]:
        return [Finding(severity="info",
                        title="Mobile-app discovery — no association files found",
                        evidence="Neither apple-app-site-association nor assetlinks.json present.",
                        remediation="No action.", url=ctx["target"])]
    sev = "info"
    if res["endpoints"]:
        sev = "low"
    findings.append(Finding(
        severity=sev,
        title=f"Mobile-app association files: {len(res['found_paths'])} found, {len(res['endpoints'])} endpoint(s)",
        evidence=(f"Files: {', '.join(res['found_paths'])}\n"
                   f"Endpoints / packages:\n  " + "\n  ".join(res['endpoints'][:20])
                   + (f"\n... +{len(res['endpoints']) - 20} more" if len(res['endpoints']) > 20 else "")),
        remediation=(
            "Review the listed endpoints — these are the URL patterns the official mobile "
            "app intercepts via universal links. If any are auth-required, ensure the same "
            "checks apply when the URL is accessed via a desktop browser (not just the app)."
        ),
        url=ctx["target"],
    ))
    return findings
