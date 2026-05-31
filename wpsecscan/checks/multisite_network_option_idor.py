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
    # v2.8.2 M9 — the v2.8.1 body-substring sniff was unreliable
    # (matched JS, theme paths, etc.). Use the REST API root namespace
    # listing as the authoritative multisite signal: a multisite install
    # exposes `network` in the discoverable namespaces, and the root
    # `/wp-json/` body includes a `_links.https://api.w.org/multisite`
    # collection link.
    root = await client.get("/wp-json/")
    is_multisite = False
    if root is not None and root.status_code == 200:
        try:
            data = root.json()
            namespaces = data.get("namespaces") if isinstance(data, dict) else []
            if isinstance(namespaces, list):
                is_multisite = any(
                    "network" in (ns or "").lower() or "multisite" in (ns or "").lower()
                    for ns in namespaces)
            if not is_multisite and isinstance(data, dict):
                # Fallback: scan _links for a multisite collection.
                links = data.get("_links") or {}
                is_multisite = any("multisite" in k.lower() for k in links.keys())
        except (ValueError, AttributeError):
            pass
    if not is_multisite:
        return [Finding(severity="info",
                         title="F11: multisite not detected via REST API (skipping IDOR probe)",
                         evidence="No multisite namespace in /wp-json/ root.",
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
