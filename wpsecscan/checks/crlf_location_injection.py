"""Item #4 — CRLF injection into Location headers on common WP redirect
endpoints.

The misc_injection_audit check already probes response *bodies* for a
generic CRLF marker, but only when --aggressive is set. CRLF in a
`Location:` header is a higher-value, low-cost passive probe worth
running on every scan: a successful injection lets an attacker plant a
`Set-Cookie` header on every visitor's first redirect (session fixation)
or smuggle a second response.

This check sends a small, throttled payload that — if naively echoed
into a Location header — would introduce a `Set-Cookie: wpsecscan-crlf-probe=1`
follower. We never look at the response *body*; we only inspect the
response's `Location` header (and `Set-Cookie` if present) for the
injected line. The probe is read-only.
"""
from __future__ import annotations

import urllib.parse

from ..http import Client
from ..models import Finding

# (param, target_path). Each entry is a redirect-style WP endpoint that
# accepts a URL-shaped value via a query parameter. The probe URL is
# percent-encoded — we deliberately include a literal %0d%0a so a naive
# decoder will materialise the line break.
_REDIRECT_PARAMS = (
    ("redirect_to", "/wp-login.php"),
    ("redirect_to", "/wp-admin/"),
    ("redirect_to", "/"),
    ("redirect",    "/"),
    ("returnurl",   "/"),
    ("return_url",  "/"),
    ("next",        "/"),
    ("url",         "/"),
)

_PROBE_PAYLOAD = "https://example.com/%0d%0aSet-Cookie:%20wpsecscan-crlf-probe=1"
_INJECTED_HEADER_NAME = "wpsecscan-crlf-probe"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    vulnerable: list[tuple[str, str, str]] = []  # (url, location_value, evidence)
    probed = 0

    for param, path in _REDIRECT_PARAMS:
        q = urllib.parse.urlencode({param: ""}) + "=" + _PROBE_PAYLOAD
        # Strip the empty value urlencode produces so we end up with `?param=PAYLOAD`.
        q = q.replace(f"{param}=&", "").replace(f"{param}==", f"{param}=")
        probe_path = f"{path}?{q}"
        step(f"probing CRLF in {param}= at {path}...")
        r = await client.get(probe_path)
        probed += 1
        if r is None:
            continue
        # We only care about responses that ARE a redirect.
        if r.status_code not in (301, 302, 303, 307, 308):
            continue
        loc = r.headers.get("location", "") or r.headers.get("Location", "")
        # Direct evidence: the injected header showed up as a follower header.
        set_cookie = r.headers.get("set-cookie", "") or r.headers.get("Set-Cookie", "")
        if _INJECTED_HEADER_NAME in set_cookie.lower():
            vulnerable.append((
                client.url(probe_path),
                loc,
                f"`Set-Cookie` contains the injected value: {set_cookie[:200]}",
            ))
            continue
        # Indirect evidence: the Location header itself contains a literal CR
        # or LF (some servers normalise %0d%0a back into raw bytes but then
        # send the whole thing as a single Location).
        if any(ch in loc for ch in ("\r", "\n")):
            vulnerable.append((
                client.url(probe_path),
                loc[:300],
                "`Location` value contains raw CR/LF characters after decoding the payload.",
            ))

    if vulnerable:
        lines = []
        for url, loc, why in vulnerable[:6]:
            lines.append(f"  - {url}\n      → Location: {loc[:160]}\n      {why}")
        findings.append(
            Finding(
                severity="high",
                title=f"CRLF injection in Location header ({len(vulnerable)} endpoint(s))",
                evidence=(
                    "An attacker-controllable redirect parameter is reflected into the "
                    "`Location` header without stripping CR/LF. This lets the attacker "
                    "inject arbitrary follower headers — most commonly `Set-Cookie` for "
                    "session fixation or HTTP-response splitting:\n\n"
                    + "\n".join(lines)
                ),
                remediation=(
                    "Reject any `redirect_to` / `returnurl` / `next` value whose decoded "
                    "form contains `\\r` or `\\n`. WordPress core's `wp_safe_redirect()` "
                    "+ `wp_validate_redirect()` already do this, so the most common cause "
                    "is a plugin or theme that builds Location values by string-concat. "
                    "Add `wp_validate_redirect()` around any custom redirect logic and "
                    "ensure your reverse proxy strips CR/LF from header values."
                ),
                url=ctx["target"],
                extra={"vulnerable_endpoints": [
                    {"url": u, "location": loc} for u, loc, _ in vulnerable[:30]
                ]},
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"CRLF Location injection — clean ({probed} endpoint(s) probed)",
                evidence=(
                    "Sent a CRLF-laden redirect payload at common WP redirect parameters "
                    "(`redirect_to`, `returnurl`, `next`, `url`, ...). None of the "
                    "responses contained the injected `Set-Cookie` follower or raw "
                    "CR/LF inside the Location header."
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
