"""F69 (v2.8.3) — distinguish cosmetic vs blocking cookie banners.

The existing `cookie_consent` check detects whether a banner HTML
element is present but does not test whether the banner is BLOCKING
(scripts only load after interaction) or COSMETIC (scripts load
regardless, banner just exists to look compliant).

We make two requests:
  1. Vanilla GET → record which tracking cookies are set
  2. GET with `Cookie: cookielawinfo-checkbox-* = no` → re-check
     whether the tracking cookies are STILL set

If the same _ga / _fbp / _ttp cookies appear in both responses, the
banner is cosmetic and the site is non-compliant with EU ePrivacy +
GDPR consent-first principles.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_TRACKING_COOKIE_NAMES = (
    "_ga", "_gid", "_gat",                 # Google Analytics
    "_fbp", "_fbc",                          # Facebook Pixel
    "_ttp", "_tt_enable_cookie",             # TikTok
    "_pin_unauth", "_pinterest_sess",        # Pinterest
    "personalization_id",                    # X / Twitter
    "fr",                                    # Facebook (legacy)
    "_hjSession", "_hjSessionUser",          # Hotjar
    "_clck", "_clsk", "MUID",                # Microsoft Clarity
)


def _tracking_cookies_in(headers) -> set[str]:
    """Extract tracking cookie names set in Set-Cookie response headers."""
    raw = []
    # httpx's Headers may have one or many Set-Cookie values; both are iterable
    try:
        # Use get_list if available (httpx specific)
        if hasattr(headers, "get_list"):
            raw = headers.get_list("set-cookie") or []
        else:
            sc = headers.get("set-cookie") or ""
            raw = [sc] if sc else []
    except (AttributeError, KeyError, TypeError):
        sc = headers.get("set-cookie", "") if hasattr(headers, "get") else ""
        raw = [sc] if sc else []
    out: set[str] = set()
    for line in raw:
        # Cookie name is everything before the first `=`
        name = (line.split("=", 1)[0] if "=" in line else line).strip()
        if name in _TRACKING_COOKIE_NAMES:
            out.add(name)
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F69: probing cookie-banner cosmetic vs blocking behavior")
    # Pass 1 — vanilla
    r1 = await client.get("/")
    if r1 is None:
        return []
    set1 = _tracking_cookies_in(r1.headers)
    body1 = (r1.text or "")
    has_banner = any(t in body1.lower() for t in
                       ("cookielawinfo", "cookiebot", "iubenda",
                        "complianz", "borlabs", "wpcoo", "cmplz"))
    if not has_banner:
        return [Finding(severity="info",
                         title="F69: no cookie banner detected",
                         evidence="None of the 7 common banner markers in homepage HTML.",
                         remediation="No action needed (or add a banner if GDPR-applicable).",
                         url=ctx["target"])]
    # Pass 2 — explicit reject via popular cookie-banner cookies
    reject_cookies = (
        "cookielawinfo-checkbox-necessary=no; "
        "cookielawinfo-checkbox-analytics=no; "
        "cookielawinfo-checkbox-marketing=no; "
        "cmplz_marketing=deny; cmplz_statistics=deny"
    )
    try:
        r2 = await client.get("/", headers={"Cookie": reject_cookies})
    except Exception:  # noqa: BLE001
        return []
    if r2 is None:
        return []
    set2 = _tracking_cookies_in(r2.headers)
    persists = set1 & set2
    if persists:
        return [Finding(severity="medium",
                         title="F69: cookie banner is COSMETIC — trackers load before consent",
                         evidence=(
                             f"Same tracking cookie(s) set on BOTH the vanilla request "
                             f"AND a reject-cookies request: {sorted(persists)}. "
                             "GDPR/ePrivacy require non-essential trackers to load only "
                             "AFTER explicit consent."),
                         remediation=(
                             "Configure the banner plugin's BLOCKING mode (most plugins call "
                             "it 'Block scripts before consent' or 'Strict mode'). For "
                             "Complianz: Wizard step 4 → 'Use plugin script-blocker'. For "
                             "CookieYes / CookieBot: enable 'Auto-blocking'. For custom "
                             "implementations, gate the GA/Pixel `<script>` tags on a "
                             "consent flag set by the banner's accept-button."),
                         url=ctx["target"])]
    return [Finding(severity="info",
                     title="F69: cookie banner appears blocking (no trackers without consent)",
                     evidence=f"Vanilla request set {sorted(set1) or 'no'} trackers; reject-cookies request set {sorted(set2) or 'no'}.",
                     remediation="No action needed.",
                     url=ctx["target"])]
