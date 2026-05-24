"""Detect plugin slugs from a curated known-bad / vendor-backdoor list.

Round-64 #55 — there is a small but real set of WP plugins that have
either (a) historically shipped with backdoors, (b) been bought by
malicious actors who then injected them, or (c) are clones of pirated
premium plugins (a classic webshell-delivery vector). This check
fingerprints each by /wp-content/plugins/<slug>/ readme.txt existence.
The list is intentionally small + conservative to keep false-positive
risk low.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Each entry: (slug, severity, reason). Adding to this list should be
# backed by a public IOC report or a CVE assigning a malware-class
# severity. Don't add a plugin here without a citeable source.
_KNOWN_BAD_OR_HIGH_RISK = (
    ("captcha-bws", "high", "Backdoor inserted by acquirer (2017 incident, removed from wp.org)"),
    ("duplicate-page-and-post", "high", "2017 backdoor incident; investigate if still installed"),
    ("display-widgets", "high", "Backdoor injected after acquisition (Sept 2017)"),
    ("woocommerce-payment-form-stripe", "critical", "Removed from wp.org for malicious code injection"),
    ("ultimate-faqs", "medium", "Historically has had multiple authn-bypass CVEs; deprecated build"),
    ("wp-mailpoet", "info", "Older versions had RCE (CVE-2014-9263); verify v3.x+"),
    ("real-time-find-replace-plugin", "high", "2024 supply-chain malware injection; investigate"),
    ("blackhole-pro-nulled", "critical", "Pirated-premium clone — typical webshell-delivery vehicle"),
    ("wp-rocket-nulled", "critical", "Pirated-premium clone — typical webshell-delivery vehicle"),
    ("elementor-pro-nulled", "critical", "Pirated-premium clone — typical webshell-delivery vehicle"),
    ("yoast-seo-nulled", "critical", "Pirated-premium clone — typical webshell-delivery vehicle"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for slug, severity, reason in _KNOWN_BAD_OR_HIGH_RISK:
        step(f"checking {slug}...")
        r = await client.get(f"/wp-content/plugins/{slug}/readme.txt")
        if r is None:
            continue
        # 200 = installed; 403 with some bytes also commonly indicates dir-listing-off but plugin present
        if r.status_code == 200 and len(r.text or "") > 50:
            findings.append(
                Finding(
                    severity=severity,
                    title=f"High-risk plugin detected: {slug}",
                    evidence=f"GET /wp-content/plugins/{slug}/readme.txt -> 200 ({len(r.text or '')} bytes)\n  Reason: {reason}",
                    remediation=(
                        f"Uninstall {slug} immediately if not strictly required. If you need this functionality, switch to a maintained alternative.\n"
                        "If it's a pirated-premium clone (\"-nulled\"), assume your site is already compromised — restore from a known-clean backup, rotate all admin credentials + salts, scan for added admin users + database triggers."
                    ),
                    url=client.url(f"/wp-content/plugins/{slug}/"),
                    extra={"slug": slug, "reason": reason},
                )
            )

    return findings
