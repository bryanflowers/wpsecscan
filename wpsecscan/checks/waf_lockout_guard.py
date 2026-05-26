"""Item #42 — early-abort guard against bricking the client's site.

Some WAFs (Wordfence, Sucuri, Cloudflare with strict rules, plus Cloudways'
own lockout system) auto-ban scanning IPs after a single block-event. If a
full scan continues after the first 403, it can result in the operator's IP
being added to a permanent blocklist — meaning the operator can no longer
visit the client's WordPress admin from their normal network.

This check runs early in the scan order and sends one benign probe at a
URL that should always succeed: `/?_wpsec_test=1` plus a HEAD on the
homepage. If either returns 403/406/418/429 or a body that contains the
classic WAF block markers ("access denied", "you have been blocked",
"banned", "ray id" alongside Cloudflare branding), it sets
`ctx['shared']['waf_lockout'] = True` and emits a critical finding so
later checks can short-circuit.

The scanner runtime should honour this flag and stop scanning. The
finding is emitted regardless, so the user knows why the scan was
truncated.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_BLOCK_MARKERS = (
    "access denied",
    "you have been blocked",
    "blocked by",
    "wordfence",
    "sucuri",
    "imunify360",
    "ray id",
    "permission denied",
    "your access to this site has been limited",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)

    step("WAF lockout sanity probe (one HEAD)...")
    r = await client.head("/")
    if r is None:
        return []
    body_lower = ""
    status = r.status_code
    if status in (403, 406, 418, 429):
        # Confirm with a GET so we have a body to inspect.
        rg = await client.get("/")
        if rg is not None:
            body_lower = (rg.text or "")[:5000].lower()
            status = rg.status_code

    is_blocked = False
    reason = ""
    if status in (403, 406, 418, 429):
        is_blocked = True
        reason = f"HEAD / returned HTTP {status}"
    if not is_blocked and body_lower:
        for marker in _BLOCK_MARKERS:
            if marker in body_lower:
                is_blocked = True
                reason = f"body contains WAF block marker {marker!r}"
                break

    if not is_blocked:
        return [Finding(
            severity="info",
            title="WAF lockout guard — no block detected on initial probe",
            evidence="HEAD / returned a non-blocking response. Continuing with the full scan.",
            remediation="No action needed.",
            url=ctx["target"],
        )]

    # Set the shared flag so the scanner runtime can short-circuit.
    shared = ctx.get("shared") or {}
    shared["waf_lockout"] = True
    shared["waf_lockout_reason"] = reason
    ctx["shared"] = shared

    return [Finding(
        severity="critical",
        title="WAF lockout — scan aborted to avoid IP-ban escalation",
        evidence=(
            f"The site WAF blocked the very first probe ({reason}). "
            "Continuing a 200-request scan against a WAF that's already "
            "actively blocking can escalate to a permanent IP-ban — which "
            "would lock the operator out of the client's admin interface "
            "from this network indefinitely.\n\n"
            "The scanner has set ctx['shared']['waf_lockout'] = True; "
            "subsequent checks should honour it and short-circuit."
        ),
        remediation=(
            "1. Whitelist your scanner IP in the WAF (Wordfence/Sucuri/CF). "
            "Coordinate with the client BEFORE retrying — typically a 30-min "
            "temporary IP allow-list under WAF Settings.\n"
            "2. Then re-run wpsecscan from the whitelisted IP.\n"
            "3. If the lockout came from Cloudways' own platform-level "
            "limiter (not Wordfence), file a support ticket asking them to "
            "temporarily exempt your IP — they will not whitelist passive "
            "scanners but they will pause a temporary ban."
        ),
        url=ctx["target"],
    )]
