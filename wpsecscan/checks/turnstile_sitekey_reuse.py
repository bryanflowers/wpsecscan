"""A32 (v2.6.0) — Cloudflare Turnstile / hCaptcha sitekey reuse.

The Turnstile / hCaptcha / reCAPTCHA sitekey is intentionally public,
but reuse is suspicious — if the same sitekey appears on unrelated
domains, an attacker may be embedding it on a phishing site that
mirrors the operator's challenge UX. Cloudflare ranks sitekey-domain
mismatch as a fraud signal.

We extract the sitekey from the homepage and surface an advisory if
the sitekey is empty/placeholder OR if Cloudflare's domain restriction
hasn't been set ("*" allows any domain to use it).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_SITEKEY_RE = re.compile(
    r'(?:data-sitekey|data-recaptcha-site|sitekey)\s*[=:]\s*["\']([\w._-]{6,80})["\']',
    re.IGNORECASE,
)
_PLACEHOLDER = ("YOUR_KEY", "your-key", "REPLACE", "TODO",
                 "0000000000000000000000", "AAAAAAAA")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Captcha sitekey scan: GET /")
    home = await client.get("/")
    html = (home.text or "") if home else ""

    keys: set[str] = set()
    for m in _SITEKEY_RE.finditer(html):
        keys.add(m.group(1))

    if not keys:
        return findings

    for k in keys:
        # Quick placeholder check
        if any(p.lower() in k.lower() for p in _PLACEHOLDER):
            findings.append(Finding(
                severity="medium",
                title=f"Captcha sitekey looks like a placeholder: {k}",
                evidence=(
                    f"Inline HTML sitekey: {k}\n"
                    "This appears to be a default/template value. The captcha\n"
                    "will not protect any form on this site."
                ),
                remediation=(
                    "Replace the sitekey with the real value from your\n"
                    "Cloudflare Turnstile / hCaptcha / reCAPTCHA dashboard."
                ),
                url=client.url("/"),
                extra={"sitekey": k},
            ))
            continue

        findings.append(Finding(
            severity="info",
            title=f"Captcha sitekey detected: {k} — verify domain allow-list",
            evidence=(
                f"Sitekey: {k}\n"
                "Sitekey-domain reuse is a phishing signal — Cloudflare ranks\n"
                "captcha-puzzle submissions higher when the sitekey is used\n"
                "outside its registered allow-list."
            ),
            remediation=(
                "In Cloudflare Turnstile / hCaptcha / reCAPTCHA dashboard,\n"
                "ensure this sitekey's 'Domains' setting is restricted to your\n"
                "apex + relevant subdomains, NOT '*' (any-origin)."
            ),
            url=client.url("/"),
            extra={"sitekey": k},
        ))
    return findings
