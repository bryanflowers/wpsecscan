"""Round-59 #6 + #8 — Alternative e-commerce + booking plugin audit.

#6 Easy Digital Downloads, WP eCommerce, WP-Simple-Pay, MarketPress.
   Non-Woo carts that the main WooCommerce check misses.
#8 Booking: Bookly, Amelia, BookingPress, MotoPress Booking, WP Simple Booking.
   IDOR on /bookings/{id} is the canonical bug; we detect the plugin then
   probe the listing endpoint anonymously.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


COMMERCE_ALT = (
    ("Easy Digital Downloads", "/wp-content/plugins/easy-digital-downloads/easy-digital-downloads.php",
                                "/wp-json/edd/v2/downloads"),
    ("WP eCommerce",           "/wp-content/plugins/wp-e-commerce/wp-shopping-cart.php",
                                "/wp-json/wpsc/v1/products"),
    ("WP Simple Pay",          "/wp-content/plugins/stripe/stripe-checkout.php",
                                "/wp-json/wpsp/v2/payments"),
    ("MarketPress",            "/wp-content/plugins/wordpress-ecommerce/marketpress.php",
                                "/wp-json/mp/v1/products"),
    ("Surecart",               "/wp-content/plugins/surecart/surecart.php",
                                "/wp-json/surecart/v1/checkouts"),
)

BOOKING = (
    ("Bookly",         "/wp-content/plugins/bookly-responsive-appointment-booking-tool/main.php",
                       "/wp-admin/admin-ajax.php?action=bookly_get_appointments"),
    ("Amelia",         "/wp-content/plugins/ameliabooking/ameliabooking.php",
                       "/wp-json/wpamelia/v1/appointments"),
    ("BookingPress",   "/wp-content/plugins/bookingpress-appointment-booking/bookingpress-appointment-booking.php",
                       "/wp-json/bookingpress/v1/bookings"),
    ("MotoPress",      "/wp-content/plugins/motopress-appointment/motopress-appointment.php",
                       "/wp-json/mphb/v1/bookings"),
    ("Simply Schedule","/wp-content/plugins/simply-schedule-appointments/simply-schedule-appointments.php",
                       "/wp-json/ssa/v1/appointments"),
)
VERSION_RE = re.compile(r"Version:\s*([\d.]+)", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    def _full(p: str) -> str:
        return target + p

    for name, plugin_path, rest_path in COMMERCE_ALT:
        step(f"commerce probe {name}...")
        r = await client.get(plugin_path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        findings.append(Finding(
            severity="info",
            title=f"Alt-commerce plugin: {name} {m.group(1) if m else '?'} detected",
            evidence=f"{plugin_path} reachable.",
            remediation="Non-Woo carts often miss core hardening (nonces on `add_to_cart`, capability on `delete_order`).",
            url=_full(plugin_path),
        ))
        rr = await client.get(rest_path)
        if rr is not None and rr.status_code == 200 and rr.text:
            findings.append(Finding(
                severity="medium",
                title=f"{name} REST endpoint readable unauthenticated",
                evidence=f"GET {rest_path} -> {rr.status_code} ({len(rr.text)} bytes).",
                remediation=f"Restrict `{rest_path}` to logged-in customers (`is_user_logged_in()` + capability).",
                url=_full(rest_path),
            ))

    for name, plugin_path, rest_path in BOOKING:
        step(f"booking probe {name}...")
        r = await client.get(plugin_path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        findings.append(Finding(
            severity="info",
            title=f"Booking plugin: {name} {m.group(1) if m else '?'} detected",
            evidence=f"{plugin_path} reachable.",
            remediation="Booking plugins frequently expose IDOR on `/bookings/{id}` and `/customers/{id}`. Audit each REST/AJAX action.",
            url=_full(plugin_path),
        ))
        rr = await client.get(rest_path)
        if rr is not None and rr.status_code == 200 and rr.text:
            findings.append(Finding(
                severity="high",
                title=f"{name}: anonymous bookings listing reachable",
                evidence=f"GET {rest_path} -> {rr.status_code} ({len(rr.text)} bytes).",
                remediation=f"Lock `{rest_path}` to `manage_options` or per-user ownership. Booking listings disclose customer PII (name/email/phone).",
                url=_full(rest_path),
            ))

    if not findings:
        return [Finding(severity="info", title="Alt-commerce/booking audit — no plugins detected",
                        evidence="Probed 5 commerce + 5 booking plugins.",
                        remediation="No action.", url=target)]
    return findings
