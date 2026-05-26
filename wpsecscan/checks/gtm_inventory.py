"""Detect Google Tag Manager container IDs in page source.

GTM containers (GTM-XXXXXXX) are not themselves secrets, but cataloguing
them publicly helps two things:
  1. Privacy inventory — every GTM container can fire arbitrary third-party
     JS, so it's a per-page list of "what else gets executed in my visitors'
     browsers".
  2. Dev / staging leakage — a staging GTM container left live in production
     ships analytics events to the wrong destination AND tells competitors
     you have a separate staging container.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_GTM_RE = re.compile(r"\b(GTM-[A-Z0-9]{4,12})\b")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("scanning homepage for GTM container IDs...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    ids = sorted(set(_GTM_RE.findall(r.text)))
    if not ids:
        return findings
    sev = "info" if len(ids) == 1 else "low"
    findings.append(Finding(
        severity=sev,
        title=f"Google Tag Manager container ID(s) in page source: {len(ids)} found",
        evidence=(
            "Container IDs detected in homepage HTML:\n"
            + "\n".join(f"  - https://tagmanager.google.com/#/container/accounts/_/containers/_/workspaces/_/tags?gtmContainerId={i}" for i in ids)
            + (
                "\n\nMultiple containers on one page is unusual — verify each is "
                "intentional. A staging-account container left in production "
                "ships analytics events to the wrong place and reveals dev "
                "infrastructure."
                if len(ids) > 1 else ""
            )
        ),
        remediation=(
            "Audit each container in tagmanager.google.com — verify ownership and "
            "intentional deployment. Remove any from disused/legacy installations. "
            "For privacy inventories, document each container's purpose and the "
            "third-party JS it loads (each GTM tag = another data-exfil vector "
            "that bypasses your CSP)."
        ),
        url=ctx["target"],
        extra={"gtm_ids": ids},
    ))
    return findings
