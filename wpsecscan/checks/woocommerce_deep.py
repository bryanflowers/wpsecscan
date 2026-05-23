"""#8 + #9 WooCommerce REST consumer-key leak + checkout-flow IDOR.

#8: scan HTML/JS for the `ck_*` / `cs_*` consumer key prefix patterns.
   These are WC REST API credentials sometimes bundled into front-end JS.

#9: probe order-status endpoints for sequential-ID IDOR — fetch /wc/store/v1
   order endpoint with adjacent IDs; if any returns 200 with order data,
   IDOR is present.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


CK_RE = re.compile(r"\b(ck_[a-f0-9]{40})\b")
CS_RE = re.compile(r"\b(cs_[a-f0-9]{40})\b")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # #8 — consumer-key leak
    step("WC: scanning homepage for ck_/cs_ tokens...")
    leaks: list[tuple[str, str]] = []
    for path in ("/", "/?page_id=2", "/wp-admin/admin-ajax.php?action=woocommerce_get_refreshed_fragments"):
        r = await client.get(path)
        if r is None:
            continue
        body = (r.text or "")[:200_000]
        for m in CK_RE.finditer(body):
            leaks.append(("WC consumer key", m.group(1)))
        for m in CS_RE.finditer(body):
            leaks.append(("WC consumer secret", m.group(1)))
    if leaks:
        findings.append(Finding(
            severity="critical",
            title=f"WooCommerce REST consumer-key/secret leaked in page HTML ({len(leaks)})",
            evidence="\n".join(f"  - {label}: {val[:8]}...{val[-4:]}" for label, val in leaks[:5]),
            remediation="Rotate the leaked key/secret in WC > Settings > Advanced > REST API. Find what wp_localize_script() call embedded it and remove. Never expose `cs_*` to the front-end — that's a secret.",
            url=ctx["target"],
        ))

    # #9 — checkout IDOR probe (best-effort; needs a known order ID)
    # We probe /wp-json/wc/store/v1/cart (unauth, always-public) to detect WC presence
    step("WC: checkout IDOR probe...")
    r = await client.get("/wp-json/wc/store/v1/cart")
    if r is not None and r.status_code == 200:
        # WC store API is present. Probe order endpoints if known
        for oid in (1, 2, 3, 100):
            r2 = await client.get(f"/wp-json/wc/v3/orders/{oid}")
            if r2 is not None and r2.status_code == 200 and "billing" in (r2.text or ""):
                findings.append(Finding(
                    severity="critical",
                    title=f"WC orders/{oid} accessible unauth — IDOR",
                    evidence=f"GET /wp-json/wc/v3/orders/{oid} returned 200 with billing data — orders should require admin auth.",
                    remediation="Restrict /wp-json/wc/v3/* to authenticated admin (default behaviour). Audit any custom REST endpoint that returns orders without `current_user_can('view_woocommerce_reports')`.",
                    url=ctx["target"] + f"/wp-json/wc/v3/orders/{oid}",
                ))
                break

    if not findings:
        return [Finding(severity="info", title="WooCommerce deep audit — no key leaks or IDORs found",
                        evidence="ck_/cs_ scan + order-endpoint probes returned clean.",
                        remediation="No action.", url=ctx["target"])]
    return findings
