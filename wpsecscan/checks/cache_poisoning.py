"""Web-cache poisoning probe.

Sends requests with attacker-controlled headers (X-Forwarded-Host,
X-Original-URL, X-Rewrite-URL) and looks for the value being reflected in
the response. If the response is cacheable (Cache-Control: public, Age
header growing), the attacker's value can be served to other visitors.

Defensive probe only — we never poison anything; we just confirm whether
the headers ARE reflected.
"""
from __future__ import annotations

import secrets

from ..http import Client
from ..models import Finding

HEADERS_TO_TRY = (
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-Scheme",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Use a random canary so reflections are unambiguous.
    canary = "wpsec-" + secrets.token_hex(6) + ".example.com"

    leaks: list[tuple[str, str]] = []  # (header, evidence)
    cacheable_url = False

    for header in HEADERS_TO_TRY:
        step(f"probing cache poisoning via {header}...")
        r = await client.get("/", headers={header: canary})
        if r is None:
            continue
        body = (r.text or "")[:80000]
        loc = r.headers.get("location", "") or r.headers.get("Location", "")
        ssrf_in_self = r.headers.get("x-pingback", "") or r.headers.get("X-Pingback", "")
        # Check reflection in body, Location header, or links
        reflected_in: list[str] = []
        if canary in body:
            reflected_in.append("body")
        if canary in loc:
            reflected_in.append("Location header")
        if canary in ssrf_in_self:
            reflected_in.append("X-Pingback")
        if not reflected_in:
            continue
        # Is the response cacheable? Cache-Control + Age headers are the markers.
        cc = (r.headers.get("cache-control", "") or r.headers.get("Cache-Control", "")).lower()
        age = (r.headers.get("age", "") or r.headers.get("Age", ""))
        # v2.8.3 H1 — fix operator precedence: Python evaluates `and`
        # before `or`, so the v2.8.2 expression only applied the
        # `no-store` + `bool(age)` guards to the `max-age` sub-clause.
        # That made `Cache-Control: public, no-store` evaluate True and
        # emit a false high-severity cache-poisoning finding. Parenthesise
        # the whole expression so all three clauses respect no-store/age.
        is_cacheable = (
            (("public" in cc) or ("s-maxage" in cc) or ("max-age" in cc))
            and ("no-store" not in cc)
            and bool(age)
        )
        if is_cacheable:
            cacheable_url = True
        ev = f"Header `{header}: {canary}` reflected in {', '.join(reflected_in)}."
        if is_cacheable:
            ev += f"\nResponse appears cacheable (Cache-Control: {cc[:80]}, Age: {age})."
        leaks.append((header, ev))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="No web-cache poisoning indicators detected",
                evidence=f"Probed {len(HEADERS_TO_TRY)} attacker-controlled headers; none reflected.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    sev = "high" if cacheable_url else "medium"
    for header, ev in leaks:
        findings.append(
            Finding(
                severity=sev,
                title=f"Cache-poisoning candidate: {header} reflected in response",
                evidence=ev,
                remediation=(
                    "At the CDN / reverse proxy, strip attacker-controllable Host-rewrite headers "
                    "(X-Forwarded-Host, X-Original-URL, X-Rewrite-URL) before they reach origin. "
                    "On Cloudflare: Transform Rules → Remove header. "
                    "If the headers must reach origin, they MUST be added to the cache key (Vary header). "
                    "Reference: https://portswigger.net/web-security/web-cache-poisoning"
                ),
                url=ctx["target"],
            )
        )
    return findings
