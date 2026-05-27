"""A11 (v2.6.0) — Stripe / WooPayments webhook endpoint audit.

WordPress payment plugins register webhook endpoints that Stripe POSTs
to on charge events. Two attack patterns:

  • The webhook endpoint accepts unsigned events (signature header
    absent or not validated) — attacker can POST forged
    `charge.succeeded` events to mark fake orders as paid.
  • The endpoint trusts the Stripe-Signature header but doesn't pin
    the secret to the LIVE secret (test-mode signatures from a
    matching test endpoint accept).

Passive: probe the common webhook paths + POST a minimal payload with
NO signature header. A 200 / 201 response is critical (signature not
required). A 400 with "missing signature" is the expected hardened
response.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_WEBHOOK_PATHS = (
    "/wp-json/wc/v3/webhooks",
    "/wc-api/wc_stripe",
    "/wc-api/wc_stripe_webhooks",
    "/wc-api/wc_gateway_stripe",
    "/wp-json/woopayments/v1/webhook",
    "/wp-json/stripe/v1/webhook",
    "/?wc-api=wc_stripe",
)

_PROBE_BODY = (
    '{"id":"evt_test_webhook","type":"charge.succeeded",'
    '"data":{"object":{"id":"ch_test","amount":1000,"status":"succeeded"}}}'
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _WEBHOOK_PATHS:
        step(f"Stripe webhook probe (no sig): {path}")
        r = await client.post(
            path,
            content=_PROBE_BODY,
            headers={"Content-Type": "application/json"},
        )
        if r is None or r.status_code in (404, 405):
            continue

        status = r.status_code
        body = (r.text or "")[:200].lower()
        # 200 / 201 / 204 without "signature" in error = no sig check
        if status in (200, 201, 204):
            findings.append(Finding(
                severity="critical",
                title=f"Stripe webhook endpoint accepts unsigned event: {path}",
                evidence=(
                    f"POST {path} with no Stripe-Signature header → HTTP {status}.\n"
                    f"Body: {body}\n"
                    "An unsigned-event-accepting webhook lets anyone POST\n"
                    "`charge.succeeded` events to mark fake orders as paid."
                ),
                remediation=(
                    "1. IMMEDIATE: disable the webhook in Stripe dashboard until\n"
                    "   signature verification is fixed.\n"
                    "2. In the plugin's webhook handler, call\n"
                    "   `Webhook::constructEvent($payload, $sig_header, $endpoint_secret)`\n"
                    "   and reject anything that throws SignatureVerificationException.\n"
                    "3. Update the plugin to its latest version; many had CVEs\n"
                    "   around webhook signature validation in 2024-2025."
                ),
                url=client.url(path),
                extra={"path": path, "status": status, "category": "payment-bypass"},
            ))
        elif status in (400, 401, 403) and ("signature" in body or "sig" in body):
            findings.append(Finding(
                severity="info",
                title=f"Stripe webhook endpoint properly requires signature: {path}",
                evidence=f"POST {path} (no sig) → HTTP {status}; body mentions signature.",
                remediation=(
                    "Endpoint is correctly auth-gated. Periodically rotate the "
                    "webhook secret via Stripe dashboard + WP plugin Settings."
                ),
                url=client.url(path),
                extra={"path": path, "status": status},
            ))

    return findings
