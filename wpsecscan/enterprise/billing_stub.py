"""Stripe metered-billing webhook scaffold.

Round-64 #122 — verifies Stripe webhook signatures + emits metered-
usage records. Stub — actual integration requires Stripe account +
metered plan setup. This module gives you the verification + record
shape; you wire it into your billing platform of choice.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


@dataclass
class MeteredUsageRecord:
    customer_id: str
    subscription_item: str
    quantity: int
    timestamp: int  # unix seconds
    action: str = "increment"  # or "set"

    def to_stripe_form(self) -> dict:
        return {
            "quantity": self.quantity,
            "timestamp": self.timestamp,
            "action": self.action,
        }


def verify_stripe_signature(payload: bytes, signature_header: str, webhook_secret: str, *, tolerance: int = 300) -> bool:
    """Verifies Stripe-Signature header. See https://docs.stripe.com/webhooks/signatures."""
    if not signature_header:
        return False
    items = dict(part.split("=", 1) for part in signature_header.split(",") if "=" in part)
    ts = items.get("t")
    sig = items.get("v1")
    if not ts or not sig:
        return False
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    if abs(time.time() - ts_int) > tolerance:
        return False
    signed = f"{ts_int}.".encode("ascii") + payload
    expected = hmac.new(webhook_secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def build_usage_record(tenant_id: str, customer_id: str, subscription_item: str, scan_count: int) -> MeteredUsageRecord:
    """Caller wires this into stripe.SubscriptionItem.create_usage_record(...)."""
    return MeteredUsageRecord(
        customer_id=customer_id,
        subscription_item=subscription_item,
        quantity=scan_count,
        timestamp=int(time.time()),
    )


# Pricing reference (not enforced here — for caller's plan setup)
DEFAULT_TIERS = {
    "free":       {"scans_per_day": 5,    "monthly_cost_usd": 0},
    "starter":    {"scans_per_day": 100,  "monthly_cost_usd": 19},
    "pro":        {"scans_per_day": 1000, "monthly_cost_usd": 99},
    "enterprise": {"scans_per_day": None, "monthly_cost_usd": None},  # custom contract
}
