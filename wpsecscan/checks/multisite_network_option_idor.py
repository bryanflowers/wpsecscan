"""F11 (v2.8.1) — Multisite network-option IDOR probe.

WordPress Multisite exposes `/wp-json/wp/v2/settings` per-site,
but some plugin-extended endpoints (e.g. WP Ultimo) expose
network-level settings under a per-site path that should require
super-admin. We probe two well-known surfaces.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F11: probing multisite network-option IDOR surfaces")
    # First confirm multisite is present.
    home = await client.get("/")
    if home is None:
        return []
    body = home.text or ""
    if "wp_is_multisite" not in body and "/sites/" not in (body[:5000].lower()):
        # Best-effort sniff; if no multisite markers, skip.
        return [Finding(severity="info",
                         title="F11: multisite markers not detected (skipping IDOR probe)",
                         evidence="No multisite signals on homepage.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    findings: list[Finding] = []
    for path in ("/wp-json/wp-ultimo/v2/sites",
                  "/wp-json/wp/v2/settings"):
        r = await client.get(path)
        if r is not None and r.status_code == 200:
            findings.append(Finding(severity="medium",
                                      title=f"F11: {path} returns 200 unauthenticated",
                                      evidence=f"GET {path} → 200 ({len(r.text or '')} bytes)",
                                      remediation=(
                                          "Verify this endpoint requires `manage_network` "
                                          "capability. If using WP Ultimo, update to >= 2.3."),
                                      url=ctx["target"]))
    return findings
