"""Detect leaked payment-webhook signing secrets in page/JS source.

Stripe, PayPal, Square use webhook-signing secrets distinct from their
public API keys. A leaked signing secret lets an attacker forge webhook
events (e.g. "order.paid") and trigger order-state changes without a
real payment. Critical — these are NOT covered by the generic
sk_live_/pk_live_ patterns in secret_leak.py.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_PATTERNS = (
    ("Stripe webhook signing secret", "critical",
     re.compile(r"\b(whsec_[A-Za-z0-9]{32,})\b")),
    ("Stripe webhook secret as `STRIPE_WEBHOOK_SECRET=`",  "critical",
     re.compile(r"STRIPE_WEBHOOK_SECRET\s*[=:]\s*[\"']?(whsec_[A-Za-z0-9]{32,})", re.IGNORECASE)),
    ("PayPal IPN/PDT signing secret in JS", "critical",
     re.compile(r"(?:IPN_HMAC_KEY|PAYPAL_HMAC)\s*[=:]\s*[\"']([A-Za-z0-9+/=]{32,})", re.IGNORECASE)),
    ("Square webhook signature key", "critical",
     re.compile(r"(?:SQUARE_WEBHOOK_SIGNATURE_KEY|SQ_WEBHOOK_KEY)\s*[=:]\s*[\"']([A-Za-z0-9+/=]{20,})", re.IGNORECASE)),
)

_SCAN_PATHS = ("/",
               "/wp-content/themes/twentytwentyfour/assets/js/scripts.js",
               "/wp-content/themes/twentytwentyfour/dist/index.js")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    bodies: list[tuple[str, str]] = []
    for p in _SCAN_PATHS:
        step(f"fetching {p} for webhook secrets...")
        r = await client.get(p)
        if r is not None and r.status_code == 200 and r.text:
            bodies.append((p, r.text))
    if not bodies:
        return findings
    seen: set[tuple[str, str]] = set()
    for name, sev, rx in _PATTERNS:
        for path, body in bodies:
            for m in rx.finditer(body):
                val = m.group(1)
                key = (name, val[:5] + val[-5:])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    severity=sev,
                    title=f"{name} exposed in page source",
                    evidence=(
                        f"Discovered at: {path}\n"
                        f"  Value (redacted): {val[:5]}***{val[-5:]} ({len(val)} chars)\n\n"
                        "Webhook signing secrets are NOT public API keys — leaking one "
                        "lets attackers forge webhook events. For Stripe, that means "
                        "fake `payment_intent.succeeded` events; for PayPal, fake IPN "
                        "callbacks; for Square, fake `payment.created` notifications. "
                        "Your back-end will trust these because the HMAC verifies."
                    ),
                    remediation=(
                        "1. ROTATE the webhook signing secret IMMEDIATELY at the "
                        "provider dashboard (Stripe Dashboard → Developers → "
                        "Webhooks → Signing secret → Roll).\n"
                        "2. Move the secret out of front-end JS / page source. It "
                        "belongs in server-side environment variables only.\n"
                        "3. Audit webhook delivery logs at the provider for any "
                        "events that hit your endpoint during the exposure window — "
                        "look for events that didn't match a real customer action."
                    ),
                    url=client.url(path),
                    extra={"secret_type": name},
                ))
    return findings
