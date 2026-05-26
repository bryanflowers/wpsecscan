"""Unauthenticated WooCommerce order IDOR probe.

A site with WooCommerce REST API exposing /wc/v3/orders/{id} unauthenticated
leaks every customer's billing email + phone + address. This is a recurring
real-world configuration bug when WC REST auth is disabled for legacy
integration testing and left that way in production.

Probes /wc/v3/orders/1..3. Fires critical if any returns 200 with
billing-shaped fields. Light probe — exactly 3 requests.
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    # First check WC namespace reachability so we don't waste 3 requests on
    # sites that don't run WooCommerce.
    head = await client.get("/wp-json/wc/v3/")
    if head is None or head.status_code != 200:
        return findings  # not WooCommerce — skip silently
    leaked: list[tuple[int, str]] = []  # (id, email)
    for oid in (1, 2, 3):
        step(f"probing /wp-json/wc/v3/orders/{oid} unauthenticated...")
        r = await client.get(f"/wp-json/wc/v3/orders/{oid}")
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        billing = data.get("billing") or {}
        email = billing.get("email") or ""
        phone = billing.get("phone") or ""
        if email or phone:
            leaked.append((oid, email or phone))
    if leaked:
        lines = "\n".join(f"  order {oid}: {redacted[:5]}***" for oid, redacted in leaked)
        findings.append(Finding(
            severity="critical",
            title=f"WooCommerce orders leaked unauthenticated ({len(leaked)} confirmed)",
            evidence=(
                f"Unauthenticated GETs to /wp-json/wc/v3/orders/{{1,2,3}} returned PII:\n{lines}\n\n"
                "Every customer order on this site is enumerable by ID without any "
                "authentication. Billing email + phone + address + line items are all "
                "exposed."
            ),
            remediation=(
                "1. IMMEDIATELY: lock /wp-json/wc/v3/orders behind authentication. "
                "Either disable the WooCommerce REST API entirely or require a valid "
                "consumer-key + consumer-secret pair.\n"
                "2. Audit access logs for sequential /orders/{N} probes to estimate "
                "scope of any prior data exposure.\n"
                "3. GDPR / state-AG: this is likely a notifiable data breach. "
                "Consult counsel on disclosure obligations."
            ),
            url=client.url("/wp-json/wc/v3/orders/"),
        ))
    return findings
