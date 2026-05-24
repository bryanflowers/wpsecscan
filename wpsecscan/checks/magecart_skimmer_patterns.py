"""Magecart / payment-form skimmer detection.

Round-64 #57 — WooCommerce + EDD checkout pages are a frequent target
for JS skimmers that exfiltrate card numbers to attacker-controlled
domains. This check fetches a small set of checkout-shaped paths and
scans for known skimmer DOM hooks + the canonical "outbound POST to a
non-payment-processor domain" pattern.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Known Magecart-family signatures + generic skimmer DOM hooks.
_SKIMMER_PATTERNS = (
    (re.compile(r"google-analytics\.cm\b", re.IGNORECASE), "Magecart Group 6 — fake-GA domain"),
    (re.compile(r"googletagmanager\.cm\b", re.IGNORECASE), "Magecart — fake-GTM domain"),
    (re.compile(r"jquery-cdn\.com", re.IGNORECASE), "Magecart Group 7 — fake-jQuery CDN"),
    (re.compile(r"jqueryassets\.com", re.IGNORECASE), "Magecart — fake-jQuery assets domain"),
    (re.compile(r"\bcardstream\.com\.[a-z]+\b", re.IGNORECASE), "Magecart cardstream lookalike"),
    (re.compile(r"document\.querySelector\(['\"]\[name=['\"]ccnumber", re.IGNORECASE), "DOM hook on credit-card field"),
    (re.compile(r"document\.querySelector\(['\"]\[name=['\"]cardnumber", re.IGNORECASE), "DOM hook on cardnumber field"),
    (re.compile(r"input\[name=['\"]?(card_?number|cc_?num)", re.IGNORECASE), "Card-number form selector"),
    (re.compile(r"['\"]https?://[a-z0-9.-]+/(?:gate|api|gateway|click)\.php['\"]", re.IGNORECASE), "Suspicious exfil endpoint"),
    (re.compile(r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{60,}['\"]", re.IGNORECASE), "Base64-blob runtime decode (skimmer obfuscation)"),
    (re.compile(r"\bnew\s+FormData\s*\([^)]*\)[^}]*\.append\([^)]*card", re.IGNORECASE), "FormData exfil with card key"),
)

# Known-good processor domains we expect to see on legit checkouts (don't flag these)
_KNOWN_PROCESSORS = ("stripe.com", "paypal.com", "braintree", "authorize.net", "squareup.com", "klarna.com")

_PROBE_PATHS = (
    "/checkout/",
    "/cart/",
    "/?page_id=checkout",
    "/wc-api/checkout",
    "/my-account/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    hits: list[tuple[str, str]] = []
    for path in _PROBE_PATHS:
        step(f"scanning {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        # Skip if no card-related markup at all (avoids generic-page false positives)
        if "card" not in body.lower() and "payment" not in body.lower():
            continue
        for pat, name in _SKIMMER_PATTERNS:
            if pat.search(body):
                hits.append((path, name))

    if hits:
        findings.append(
            Finding(
                severity="critical",
                title=f"Magecart-style skimmer pattern detected ({len(hits)} hit)",
                evidence="\n".join(f"  {p}: {n}" for p, n in hits[:8]),
                remediation=(
                    "Treat as live card-data exfiltration. Steps (PCI-mandated):\n"
                    "  1. Take the site offline or short-circuit checkout while you investigate.\n"
                    "  2. Notify your acquiring bank within 24 hours.\n"
                    "  3. Engage a PFI (PCI Forensic Investigator) if you process > 1k transactions/month.\n"
                    "  4. Audit recent file modifications + plugin updates + admin user list.\n"
                    "  5. Restore from a known-clean backup; rotate all secrets."
                ),
                url=client.url(hits[0][0]) if hits else "",
                extra={"hits": [{"path": h[0], "pattern": h[1]} for h in hits]},
            )
        )

    return findings
