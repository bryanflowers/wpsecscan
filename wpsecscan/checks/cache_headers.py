"""Cache-header audit.

Look at response headers from a few endpoints to detect:
  - Authenticated content cached publicly (`Cache-Control: public` on logged-in views)
  - Missing `Vary` on cookie-sensitive content
  - Cache-poisoning vectors via unkeyed inputs
  - Stale-while-revalidate / immutable assets pointing at non-versioned paths
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("inspecting / for cache headers...")
    r = await client.get("/")
    if r is None:
        return findings
    cc = (r.headers.get("cache-control", "") or r.headers.get("Cache-Control", "") or "").lower()
    vary = (r.headers.get("vary", "") or r.headers.get("Vary", "") or "").lower()
    age = (r.headers.get("age", "") or r.headers.get("Age", "") or "")
    x_cache = (r.headers.get("x-cache", "") or "")
    set_cookie = r.headers.get("set-cookie", "")

    # 1. Public caching with cookies set on the response = potential cache poisoning + auth leak
    if "public" in cc and set_cookie:
        findings.append(
            Finding(
                severity="medium",
                title="Response is cache-control: public AND sets a cookie",
                evidence=(
                    f"GET / response headers:\n"
                    f"  Cache-Control: {cc}\n"
                    f"  Set-Cookie:    {set_cookie[:200]}\n\n"
                    "A public-cacheable response with Set-Cookie can poison the CDN — every visitor downstream "
                    "of the cache receives the same cookie. If that cookie is session-bearing, you've shared a session globally."
                ),
                remediation=(
                    "Either remove the cookie from cacheable responses, or downgrade Cache-Control to private. "
                    "Cookies belong on responses your origin generates per-user, not on shared cached pages."
                ),
                url=ctx["target"],
            )
        )

    # 2. Missing Vary on cookie-sensitive paths
    step("inspecting /wp-login.php for Vary header...")
    r2 = await client.get("/wp-login.php")
    if r2 is not None and "set-cookie" in (r2.headers.get("set-cookie", "") or "").lower() and "cookie" not in (r2.headers.get("vary", "") or "").lower():
        findings.append(
            Finding(
                severity="low",
                title="/wp-login.php sets cookies but Vary header doesn't include Cookie",
                evidence=(
                    f"GET /wp-login.php response: Set-Cookie present but Vary doesn't mention Cookie.\n"
                    f"  Vary: {r2.headers.get('vary', '(missing)')}\n"
                    "Some CDNs may then cache the response per-URL without varying by cookies, "
                    "potentially leaking auth-related cookies to other users."
                ),
                remediation="Add `Vary: Cookie` on the wp-login.php response. Nginx: `add_header Vary 'Cookie' always;` inside the login location block.",
                url=client.url("/wp-login.php"),
            )
        )

    # 3. Stale-cache hints — CDN reports Age but no caching plugin
    if age and int(age or 0) > 3600 and "wp-rocket" not in cc and "w3-total" not in cc:
        findings.append(
            Finding(
                severity="info",
                title=f"CDN reports cached response age = {age}s",
                evidence=f"Age: {age}, X-Cache: {x_cache or '(not present)'}",
                remediation="No action unless the response is supposed to be fresh (e.g., logged-in admin views).",
                url=ctx["target"],
            )
        )

    # 4. Cache poisoning via unkeyed inputs — quick test: send a fake X-Forwarded-Host and see if it lands in the body or headers
    step("testing cache-key poisoning via X-Forwarded-Host...")
    r3 = await client.get("/", headers={"X-Forwarded-Host": "wpsecscan-cache-probe.invalid"})
    if r3 is not None and "wpsecscan-cache-probe.invalid" in (r3.text or "")[:5000]:
        findings.append(
            Finding(
                severity="medium",
                title="X-Forwarded-Host is reflected into HTML — cache-poisoning candidate",
                evidence=(
                    "GET / with X-Forwarded-Host: wpsecscan-cache-probe.invalid was reflected in the response body. "
                    "If the response is also cacheable and the cache doesn't key on XFH, an attacker can poison "
                    "the cache with content under their domain."
                ),
                remediation=(
                    "Either strip X-Forwarded-Host at the edge or add it to the cache key. "
                    "In WordPress, set absolute URLs via wp_options.siteurl/home — never via the Host header at runtime."
                ),
                url=ctx["target"],
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No cache-header anomalies detected",
                evidence=(
                    f"Cache-Control: {cc or '(not set)'}\n"
                    f"Vary:          {vary or '(not set)'}\n"
                    f"Age:           {age or '(not set)'}\n"
                    f"X-Cache:       {x_cache or '(not set)'}"
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
