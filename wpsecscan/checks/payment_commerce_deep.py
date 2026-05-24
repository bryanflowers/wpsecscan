"""Round-59 #58-62 — Payment / commerce deep audit.

#58 Stripe/PayPal/Square config — detect each plugin + check that
   `pk_test_` keys aren't accidentally leaking in production HTML.
#59 PCI-DSS 4.0 checklist (informational guidance per finding)
#60 PCI evidence mode — emit a JSON evidence pack alongside findings
   so QSAs can include in their workpaper.
#61 3DS2 check — does the merchant's Stripe/PayPal integration enforce
   3DS2 on EU cards? Best-effort via the JS init params.
#62 Order/refund IDOR — `/wp-admin/admin-ajax.php?action=woocommerce_get_refunded_order_items&order_id=N`
   without auth.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from ..http import Client
from ..models import Finding


PAYMENT_PLUGINS = (
    ("Stripe (official)",      "/wp-content/plugins/woocommerce-gateway-stripe/woocommerce-gateway-stripe.php"),
    ("WP Simple Pay (Stripe)", "/wp-content/plugins/stripe/stripe-checkout.php"),
    ("PayPal Standard",        "/wp-content/plugins/woocommerce-paypal-payments/woocommerce-paypal-payments.php"),
    ("PayPal for WP",          "/wp-content/plugins/wp-paypal/wp-paypal.php"),
    ("Square",                 "/wp-content/plugins/woocommerce-square/woocommerce-square.php"),
    ("Authorize.Net",          "/wp-content/plugins/woocommerce-gateway-authorize-net-cim/woocommerce-gateway-authorize-net-cim.php"),
)

# These regexes detect TEST keys in production HTML — the classic leak.
TEST_KEY_RES = (
    re.compile(r"\bpk_test_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk_test_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAR-[0-9]{10,}-S"),  # PayPal sandbox client id pattern
)

THREE_DS_RE = re.compile(r"(request_three_d_secure|three_d_secure|3ds2|sca_required|payment_method_options)", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    seen = []
    for name, path in PAYMENT_PLUGINS:
        step(f"payment probe {name}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        seen.append(name)

    if not seen:
        return [Finding(severity="info", title="Payment-commerce audit — no payment plugins detected",
                        evidence="Probed 6 popular payment plugins.",
                        remediation="No action.", url=target)]

    findings.append(Finding(
        severity="info",
        title=f"Payment plugin(s) detected: {', '.join(seen)}",
        evidence="",
        remediation="Audit each integration's webhook signature verification + 3DS2 enforcement.",
        url=target,
    ))

    # ---- #58 test-key leak in production HTML ----
    home = await client.get("/")
    checkout = await client.get("/checkout/") or await client.get("/cart/")
    bodies = [(home.text or "") if home else "", (checkout.text or "") if checkout else ""]
    for body in bodies:
        for r in TEST_KEY_RES:
            for m in r.finditer(body):
                findings.append(Finding(
                    severity="critical",
                    title=f"Test/sandbox payment key leaked in production HTML: {m.group(0)[:14]}...",
                    evidence="Pattern matched in front-end HTML.",
                    remediation="Replace the sandbox/test key with the live key. ROTATE the leaked test key in the payment-provider dashboard regardless.",
                    url=target,
                ))

    # ---- #59 PCI-DSS 4.0 checklist (informational, one finding) ----
    findings.append(Finding(
        severity="info",
        title="PCI-DSS 4.0 — checklist for sites taking cards",
        evidence=("Key 4.0 controls:\n"
                  "  6.4.3 — script integrity on payment page (SRI)\n"
                  "  11.6.1 — change/script-tamper detection on payment page\n"
                  "  3.5.1.2 — disk-encryption for any cardholder backup\n"
                  "  8.4 — MFA on all access to CDE\n"
                  "  12.10 — IR plan, tested annually"),
        remediation="Document SAQ-A (host fully outsourced to Stripe Elements/PayPal hosted-fields) or SAQ-A-EP. The latter requires script-integrity monitoring on the checkout page.",
        url=target,
    ))

    # ---- #60 PCI evidence mode (emit JSON pack alongside findings) ----
    try:
        import os
        ev_dir = Path(os.environ.get("WPSECSCAN_PCI_EVIDENCE_DIR")
                       or (os.environ.get("WPSECSCAN_HOME") or str(Path.home() / ".wpsecscan")))
        ev_dir = ev_dir / "pci_evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        # Reject path-traversal/funky names
        safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:80] or "scan"
        evidence = {
            "target": target,
            "payment_plugins": seen,
            "scan_module": "payment_commerce_deep",
            "controls_covered": ["6.4.3", "11.6.1", "3.5.1.2", "8.4", "12.10"],
        }
        ev_path = ev_dir / f"{safe_host}.json"
        # Symlink guard
        if ev_path.is_symlink():
            ev_path.unlink()
        ev_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        findings.append(Finding(
            severity="info",
            title="PCI evidence pack written",
            evidence=f"Wrote {ev_path}",
            remediation="Attach this JSON to your SAQ workpaper.",
            url=target,
        ))
    except (OSError, ValueError):
        pass

    # ---- #61 3DS2 best-effort detection ----
    body_blob = (home.text or "") + ((checkout.text or "") if checkout else "")
    if "Stripe" in " ".join(seen) and not THREE_DS_RE.search(body_blob):
        findings.append(Finding(
            severity="medium",
            title="Stripe integration without 3DS2 hint in HTML",
            evidence="No `request_three_d_secure` / `payment_method_options` reference found in checkout HTML.",
            remediation=("Set `request_three_d_secure: 'automatic'` on the PaymentIntent. PSD2 SCA "
                         "is required on EU cards — without it, transactions are decline-eligible."),
            url=target,
        ))

    # ---- #62 Order/refund IDOR ----
    step("commerce: order IDOR probe...")
    for action in ("woocommerce_get_refunded_order_items", "woocommerce_load_order_items"):
        r = await client.get(f"/wp-admin/admin-ajax.php?action={action}&order_id=1")
        if r is not None and r.status_code == 200 and r.text and r.text.strip() not in ("0", "-1"):
            findings.append(Finding(
                severity="high",
                title=f"WooCommerce AJAX action `{action}` reachable unauthenticated",
                evidence=f"GET ...?action={action}&order_id=1 -> 200, body={r.text[:120]}",
                remediation=("This AJAX endpoint must check `current_user_can('edit_shop_orders')`. "
                             "Patch in `class-wc-ajax.php` or upgrade WooCommerce."),
                url=target + "/wp-admin/admin-ajax.php",
            ))

    return findings
