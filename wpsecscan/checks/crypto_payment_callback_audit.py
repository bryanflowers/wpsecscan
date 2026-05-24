"""Crypto-payment webhook callback audit.

Round-64 #73 — WooCommerce-Crypto + similar plugins receive payment-
confirmation webhooks at /wp-json/<plugin>/v1/callback or
/?wc-api=<plugin>. Without HMAC or signature verification, an attacker
can spoof a "payment confirmed" callback and mark unpaid orders as paid.
This check probes a handful of known endpoints with a crafted callback,
flagging any that respond 200 without challenge.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Each entry: (path, sample-body) — payment-confirm shaped
_CALLBACK_PROBES = (
    ("/?wc-api=WC_Gateway_Coinbase_Commerce", {"event": {"type": "charge:confirmed", "data": {"id": "X"}}}),
    ("/wp-json/wc/v3/coinbase/callback", {"event": "charge:confirmed", "data": {"id": "X"}}),
    ("/wp-json/woocommerce-crypto/v1/callback", {"tx": "0x0", "status": "confirmed", "order_id": 1}),
    ("/wp-json/blockonomics/v1/callback", {"status": 2, "addr": "X", "value": 1000}),
    ("/?wc-api=BTCPay_Server", {"invoiceId": "X", "status": "paid"}),
    ("/wp-json/wc-eth-payments/v1/callback", {"tx_hash": "0x0", "status": "confirmed", "order_id": 1}),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path, body in _CALLBACK_PROBES:
        step(f"probing {path}...")
        r = await client.post(path, json=body, headers={"Content-Type": "application/json"})
        if r is None:
            continue
        if r.status_code == 404:
            continue
        # 401/403 with auth-related message = good
        body_text = (r.text or "").lower()
        if r.status_code in (401, 403) or "signature" in body_text or "invalid" in body_text or "hmac" in body_text:
            continue
        # 200 without any challenge = critical
        if r.status_code == 200:
            findings.append(
                Finding(
                    severity="critical",
                    title=f"Crypto-payment callback accepts unauthenticated POST: {path}",
                    evidence=f"POST {path} returned 200 to a spoof callback.\n  Body (first 200): {(r.text or '')[:200]!r}",
                    remediation=(
                        "Add HMAC-SHA256 signature verification on the callback. The crypto-payment provider should sign the body with a shared secret you configure once.\n"
                        "Without this, an attacker can mark any order paid by POSTing a fake callback."
                    ),
                    url=client.url(path),
                )
            )
        # Some gateways respond 200 + JSON error body — try to detect
        elif r.status_code in (200, 400) and "ok" in body_text[:20]:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Crypto-payment callback returned 'ok' for spoof: {path}",
                    evidence=f"POST {path} -> {r.status_code}\n  Body starts with 'ok' — likely no auth",
                    remediation="Verify the gateway requires a signature header. If not, switch to a gateway that does (Coinbase Commerce, BTCPay all support HMAC).",
                    url=client.url(path),
                )
            )

    return findings
