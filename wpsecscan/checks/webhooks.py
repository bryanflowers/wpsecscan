"""Webhook endpoint discovery.

Many WP plugins register webhook receivers under `/wp-json/<plugin>/v1/webhook`
or `/?wc-api=<plugin>` and many forget to validate signatures or restrict
sources. This check discovers them and probes for the auth requirement.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (path, plugin, what-it-handles)
KNOWN_WEBHOOK_PATHS = (
    # WooCommerce
    ("/?wc-api=stripe",                                      "WooCommerce Stripe Gateway"),
    ("/?wc-api=WC_Gateway_Stripe",                            "WooCommerce Stripe"),
    ("/?wc-api=WC_Gateway_PayPal",                            "WooCommerce PayPal"),
    ("/?wc-api=ck",                                          "WooCommerce ConvertKit"),
    ("/?wc-api=mailchimp",                                   "WC Mailchimp"),
    # REST-based webhooks
    ("/wp-json/wc/v3/webhooks",                              "WooCommerce REST webhooks list"),
    ("/wp-json/stripe/v1/webhook",                           "Stripe REST webhook"),
    ("/wp-json/wp-webhooks/v1/webhook",                      "WP Webhooks generic"),
    ("/wp-json/gf/v2/forms",                                 "Gravity Forms REST"),
    ("/wp-json/zapier/v1/triggers",                          "Zapier integration"),
    ("/wp-json/integromat/v1/scenarios",                     "Make/Integromat"),
    ("/wp-json/wp-mail-smtp/v1/test",                        "WP Mail SMTP test endpoint"),
    # Form-handler webhooks
    ("/wp-json/contact-form-7/v1/contact-forms",             "Contact Form 7"),
    ("/wp-json/wpforms/v1/forms",                            "WPForms"),
    ("/wp-json/wpforms-mailchimp/v1/webhook",                "WPForms-Mailchimp"),
    # Generic webhook plugins
    ("/wp-content/plugins/webhooks/webhook.php",             "Generic webhooks plugin"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    discovered: list[dict] = []
    for path, plugin in KNOWN_WEBHOOK_PATHS:
        step(f"probing webhook endpoint {path}...")
        r = await client.get(path)
        if r is None or r.status_code not in (200, 401, 403, 405):
            continue
        body = (r.text or "")[:1000]
        # 401/403 = endpoint exists but rejects anon — that's the right answer
        # 200 with substantive body = endpoint serves data unauthenticated (bad)
        sev = "info" if r.status_code in (401, 403) else (
            "medium" if r.status_code == 200 and len(body) > 50 else "info"
        )
        discovered.append({
            "path": path,
            "plugin": plugin,
            "status": r.status_code,
            "severity": sev,
            "body_preview": body[:200],
        })

    if not discovered:
        findings.append(
            Finding(
                severity="info",
                title="No webhook endpoints discovered",
                evidence=f"Probed {len(KNOWN_WEBHOOK_PATHS)} known webhook paths; none responded as endpoints.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Group findings: one info-level summary + one per concerning endpoint
    auth_gated = [d for d in discovered if d["status"] in (401, 403)]
    accessible = [d for d in discovered if d["status"] == 200]

    findings.append(
        Finding(
            severity="info",
            title=f"Webhook surface: {len(discovered)} endpoint(s) found ({len(auth_gated)} auth-gated, {len(accessible)} open)",
            evidence="\n".join(
                f"  - {d['path']:60} HTTP {d['status']:>3}  ({d['plugin']})" for d in discovered
            ),
            remediation=(
                "Webhook endpoints should verify signatures from the sender (Stripe-Signature, "
                "X-WC-Webhook-Signature, etc.). Audit each plugin's webhook handler — most have a "
                "documented secret/signature check that operators sometimes leave blank."
            ),
            url=ctx["target"],
        )
    )

    for d in accessible:
        if "webhook" in d["path"].lower() or "wc-api" in d["path"].lower():
            findings.append(
                Finding(
                    severity=d["severity"],
                    title=f"Open webhook endpoint: {d['plugin']} at {d['path']}",
                    evidence=(
                        f"GET {d['path']} -> 200, {len(d['body_preview'])} bytes\n"
                        f"  Plugin: {d['plugin']}\n"
                        f"  body preview: {d['body_preview'][:160]!r}"
                    ),
                    remediation=(
                        f"Audit the {d['plugin']} webhook handler. Look for `verify_signature()` or equivalent. "
                        "Most webhook plugins ship with a 'webhook secret' field that must be configured."
                    ),
                    url=client.url(d["path"]),
                )
            )
    return findings
