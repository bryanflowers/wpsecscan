"""F19 (v2.8.1) — WooCommerce multi-vendor (Dokan/WCFM) IDOR probe.

Dokan + WCFM allow vendors to manage their products via REST.
Historical IDOR bugs let vendor A read/edit vendor B's products by
incrementing an ID. We fingerprint the plugin and emit a
moderate-severity advisory pointing to CVE histories.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F19: probing multi-vendor plugins")
    detected = []
    for path, label, cve in (
        ("/wp-content/plugins/dokan-lite/", "Dokan-Lite",
         "CVE-2024-32833 (vendor IDOR pre-3.10.4)"),
        ("/wp-content/plugins/dokan-pro/", "Dokan-Pro",
         "CVE-2024-32833 (vendor IDOR pre-3.10.4)"),
        ("/wp-content/plugins/wc-frontend-manager/", "WCFM-Frontend-Manager",
         "CVE-2024-3812 (vendor IDOR pre-6.6.0)"),
        ("/wp-content/plugins/wc-multivendor-marketplace/", "WCFM-Marketplace",
         "CVE-2024-3813 (vendor IDOR pre-3.6.7)"),
    ):
        r = await client.head(path)
        if r is not None and r.status_code in (200, 301, 302, 403):
            detected.append((label, cve))
    if not detected:
        return [Finding(severity="info",
                         title="F19: no multi-vendor plugins detected",
                         evidence="None of the 4 fingerprinted multi-vendor plugin paths responded.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    lines = [f"{lbl} → {cve}" for lbl, cve in detected]
    return [Finding(severity="medium",
                     title=f"F19: {len(detected)} multi-vendor plugin(s) detected — IDOR-history audit required",
                     evidence="\n".join(lines),
                     remediation=(
                         "Confirm plugin versions are >= the patched releases above. "
                         "Audit any custom vendor-dashboard endpoints for "
                         "`current_user_can('manage_woocommerce')` OR an explicit "
                         "ownership check that compares `get_post_field('post_author')` "
                         "to `get_current_user_id()`."),
                     url=ctx["target"])]
