"""A20 (v2.6.0) — IAB TCF v2.2 cookie-consent desync.

Many WP cookie-banner plugins (Cookie Notice, CookieYes, Complianz,
Iubenda) set a `cookielawinfo-checkbox-*` consent cookie when the user
accepts; the analytics cookies (`_ga`, `_fbp`, `__hssc`, `_pin_unauth`,
`_uetsid`) should only fire AFTER consent.

Passive: GET / with NO cookies, scan response Set-Cookie + inline
<script> tags for analytics cookies firing pre-consent. The mere
PRESENCE of `_ga` in Set-Cookie before any consent interaction is the
violation.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_TRACKING_COOKIES = (
    "_ga", "_gid", "_gat", "_fbp", "__hssc", "__hstc",
    "_pin_unauth", "_uetsid", "_uetvid", "MUID",
    "intercom-id", "intercom-session", "_hjSession",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Cookie-consent desync: GET / (no cookies)")
    r = await client.get("/", headers={"Cookie": ""})
    if r is None:
        return findings

    sc = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else [r.headers.get("set-cookie", "")]
    if isinstance(sc, str):
        sc = [sc]

    pre_consent: list[str] = []
    for header in sc:
        if not header:
            continue
        for name in _TRACKING_COOKIES:
            if re.match(rf"^\s*{re.escape(name)}\s*=", header):
                pre_consent.append(name)

    if pre_consent:
        unique = sorted(set(pre_consent))
        findings.append(Finding(
            severity="medium",
            title=f"Tracking cookies set before consent: {', '.join(unique)}",
            evidence=(
                "Anonymous GET / returned Set-Cookie headers for tracking "
                f"cookies: {', '.join(unique)}.\n"
                "Per ePrivacy + GDPR + IAB TCF v2.2, analytics/marketing "
                "cookies MUST NOT fire until the user accepts the banner. "
                "This is a textbook ePrivacy violation."
            ),
            remediation=(
                "1. Audit your cookie-banner plugin's 'block tags' or 'script "
                "blocker' feature — it should rewrite analytics <script> tags "
                "to type='text/plain' until consent is granted.\n"
                "2. Move analytics initialization into the cookie-banner's "
                "consent callback ('onAccept'), not into the page <head>."
            ),
            url=client.url("/"),
            extra={"cookies_pre_consent": unique},
        ))

    return findings
