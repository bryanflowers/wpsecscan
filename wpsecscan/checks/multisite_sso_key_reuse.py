"""A13 (v2.6.0) — WordPress Multisite SSO HMAC key reuse.

WP Multisite networks that ship a custom SSO between sub-sites often
reuse a single SECRET_AUTH_KEY across the network. When that key
leaks (via wp-config.php exposure, backup file, GitHub repo), an
attacker can forge auth cookies for ANY sub-site.

Probe approach: identify multisite via the standard fingerprints (the
existing `multisite` check covers this); cross-check whether the
sub-site cookies share the same `Path=/` scope (a per-site cookie
restricted to its sub-path is much safer).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_MS_FINGERPRINTS = (
    "/wp-admin/network/",
    "/wp-content/sunrise.php",
    "?wp-network-admin",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Cheap multisite fingerprint (independent of the heavier multisite check)
    step("Multisite SSO probe: home + admin")
    home = await client.get("/")
    home_body = (home.text or "") if home else ""
    is_multisite = "wp-admin/network" in home_body

    if not is_multisite:
        r = await client.get("/wp-admin/network/")
        if r is not None and r.status_code in (200, 302, 403):
            is_multisite = True

    if not is_multisite:
        return findings

    # Look for site-wide cookie scope on /wp-login.php
    step("Multisite cookie-scope check")
    lg = await client.get("/wp-login.php")
    if lg is None:
        return findings

    set_cookies = lg.headers.get_list("set-cookie") if hasattr(lg.headers, "get_list") else [lg.headers.get("set-cookie", "")]
    if isinstance(set_cookies, str):
        set_cookies = [set_cookies]

    network_scoped = []
    for sc in set_cookies:
        if not sc:
            continue
        # WP login cookies named wordpress_test_cookie / wordpress_logged_in_*
        if "wordpress_" in sc and re.search(r"path\s*=\s*/(?:;|$)", sc, re.IGNORECASE):
            network_scoped.append(sc[:120])

    if network_scoped:
        findings.append(Finding(
            severity="medium",
            title="WP Multisite cookies scoped to / (network-wide) — verify SSO key isolation",
            evidence=(
                "Login Set-Cookie headers use Path=/ — every sub-site shares\n"
                "the cookie scope. If SECRET_AUTH_KEY / SECRET_NONCE_KEY etc.\n"
                "in wp-config.php are SHARED across the network, a leak of\n"
                "one sub-site's cookies validates against any other.\n"
                "Sample Set-Cookie headers:\n  "
                + "\n  ".join(network_scoped[:5])
            ),
            remediation=(
                "1. Audit wp-config.php — confirm SECRET_AUTH_KEY etc. are SET\n"
                "   (not the default placeholders) and rotated quarterly.\n"
                "2. If sub-sites have very different trust levels, use the\n"
                "   COOKIE_DOMAIN constant to scope cookies per-subsite.\n"
                "3. Rotate SECRET_* keys NOW if wp-config.php has ever been\n"
                "   committed to a public repo or backed up to a public bucket."
            ),
            url=client.url("/wp-login.php"),
            extra={"cookies_sample": network_scoped[:5]},
        ))

    return findings
