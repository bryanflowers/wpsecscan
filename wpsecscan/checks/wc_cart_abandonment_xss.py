"""F2 (v2.8.1) — WC cart-abandonment plugin stored-XSS probe.

Retainful, CartFlows Cart Abandonment Recovery, and WooCommerce Cart
Abandonment Recovery all collect guest emails on the checkout page
and render them server-side in admin email templates. Pre-2024 CVE
disclosures showed several mis-rendered the email field unescaped.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_FINGERPRINTS = (
    "/wp-content/plugins/woo-cart-abandonment-recovery/",
    "/wp-content/plugins/cartflows-ca/",
    "/wp-content/plugins/retainful/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    found: list[str] = []
    step = ctx.get("step") or (lambda _s: None)
    for path in _FINGERPRINTS:
        step(f"F2: probing {path}")
        r = await client.head(path)
        if r is not None and r.status_code in (200, 301, 302, 403):
            found.append(path)
    if not found:
        return [Finding(severity="info",
                         title="F2: WC cart-abandonment plugin not detected",
                         evidence="None of Retainful/CartFlows-CA/WC-CAR present.",
                         remediation="No action needed.", url=ctx["target"])]
    return [Finding(severity="medium",
                     title=f"F2: cart-abandonment plugin(s) present ({len(found)}); audit email-template escaping",
                     evidence="Detected:\n" + "\n".join(f"  - {p}" for p in found),
                     remediation=(
                         "These plugins render guest emails in admin email "
                         "templates; verify the plugin is updated to a "
                         "post-CVE-2024 version (Retainful >= 1.16.1, CartFlows-CA "
                         ">= 1.10.0, WC-CAR >= 1.3.0). Consider a WAF rule that "
                         "strips HTML from the email field on submission as defence "
                         "in depth."),
                     url=ctx["target"])]
