"""GDPR / ePrivacy cookie-consent audit.

Loads the homepage WITHOUT any consent (fresh browser equivalent) and checks:
  1. Are non-essential cookies set on first page load? (analytics, marketing,
     third-party tracking) — that's a GDPR/ePrivacy violation in the EU.
  2. Is there a visible cookie banner in the HTML (heuristic)?

We don't try to BLOCK / accept the banner — we just check the cookies that
arrive on the first request and the presence of a banner in the rendered HTML.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Cookies that are commonly set by analytics/marketing scripts — should NOT
# arrive on first load if the site complies with ePrivacy.
NON_ESSENTIAL_COOKIE_PATTERNS = (
    r"^_ga",        # Google Analytics
    r"^_gid",       # GA
    r"^_gat",       # GA
    r"^_fbp",       # Facebook Pixel
    r"^_fbc",       # FB click
    r"^fr$",        # FB
    r"^_hjid",      # Hotjar
    r"^_hjSession", # Hotjar
    r"^_uetsid",    # Microsoft UET
    r"^_uetvid",    # Microsoft UET
    r"^MUID$",      # MS Ads
    r"^ajs_anon",   # Segment
    r"^mp_",        # Mixpanel
    r"^amplitude_", # Amplitude
    r"^IDE$",       # DoubleClick
    r"^NID$",       # Google
    r"^__utm",      # Old GA
    r"^lvt$",       # Linkedin
    r"^li_",        # Linkedin
    r"^bcookie$",   # Linkedin
)

# Heuristic markers for a cookie consent banner in HTML
BANNER_MARKERS = (
    "cookie consent", "cookie notice", "cookie banner", "cookie-bar",
    "cookielawinfo", "cookieyes", "complianz", "borlabs", "iubenda",
    "onetrust", "cookiebot", "klaro", "termly", "cookie-script",
    "consent-banner", "we use cookies", "this site uses cookies",
    "accept cookies", "manage cookies", "your privacy",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching / with a fresh-browser cookie jar...")
    r = await client.get("/")
    if r is None:
        findings.append(
            Finding(
                severity="info",
                title="Cookie-consent audit — no response from /",
                evidence="GET / returned no body.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Parse Set-Cookie headers
    cookie_headers = []
    if hasattr(r.headers, "get_list"):
        cookie_headers = r.headers.get_list("set-cookie")
    else:
        # Fallback: single header value or raw list
        sc = r.headers.get("set-cookie", "") or r.headers.get("Set-Cookie", "")
        if sc:
            cookie_headers = [sc]

    cookie_names: list[str] = []
    for header in cookie_headers:
        # "name=value; Path=/; HttpOnly..."  — first segment before ;
        name = header.split("=", 1)[0].strip()
        if name:
            cookie_names.append(name)

    non_essential = []
    for name in cookie_names:
        for pat in NON_ESSENTIAL_COOKIE_PATTERNS:
            if re.match(pat, name, re.IGNORECASE):
                non_essential.append(name)
                break

    body = (r.text or "")[:200000].lower()
    has_banner = any(marker in body for marker in BANNER_MARKERS)

    if non_essential and not has_banner:
        findings.append(
            Finding(
                severity="high",
                title=f"{len(non_essential)} non-essential cookie(s) set on first load and no consent banner visible",
                evidence=(
                    f"Cookies set: {', '.join(sorted(set(non_essential)))}\n"
                    "These cookies require prior opt-in consent under GDPR + ePrivacy in the EU "
                    "(and similar laws in UK, CH, BR). No consent banner appears in the homepage HTML "
                    "(checked against 20+ common consent-plugin markers)."
                ),
                remediation=(
                    "Install a consent-management platform (Complianz, CookieYes, Cookiebot, Klaro, "
                    "Termly, Borlabs). Configure it to BLOCK third-party scripts (gtag, fbq, hotjar) "
                    "until the user clicks Accept. Pre-loaded tracking cookies are a top-5 GDPR "
                    "enforcement case under €/£/CHF jurisdictions."
                ),
                url=ctx["target"],
            )
        )
    elif non_essential and has_banner:
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(non_essential)} non-essential cookie(s) set before consent (despite banner present)",
                evidence=(
                    f"Cookies: {', '.join(sorted(set(non_essential)))}\n"
                    "A consent banner is visible in the HTML, but cookies arrived BEFORE any "
                    "user interaction. That's still non-compliant — the banner is decorative."
                ),
                remediation=(
                    "Re-configure the consent plugin to actually block / dequeue tracking scripts "
                    "until consent. Most plugins default to 'cookie-information mode' which doesn't "
                    "block — switch to 'cookie-blocker' or 'pre-consent script management' mode."
                ),
                url=ctx["target"],
            )
        )
    elif not non_essential and not has_banner:
        findings.append(
            Finding(
                severity="info",
                title="No non-essential cookies on first load, no consent banner needed",
                evidence=f"Cookies set: {cookie_names or '(none)'}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title="Cookie-consent posture looks compliant",
                evidence=(
                    f"No non-essential cookies pre-consent. Banner markers present: "
                    f"{has_banner}. Cookies on first load: {cookie_names or '(none)'}."
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
    return findings
