"""Round-59 #52-57 — CDN / edge audit.

#52 Cloudflare Workers route exposure — does the apex have a Worker
   handling /api/* or /admin/* without auth?
#53 CloudFront signed-URL bypass — strip Signature= and Policy=, does
   the resource still serve?
#54 Bunny / KeyCDN config probes — Origin-Shield header presence
#55 Edge cache TTL audit — Cache-Control + Cloudflare cf-cache-status
#56 Origin-pull header injection — does the origin honour X-Original-Host
   from edge?
#57 CDN purge-API auth — is the CDN admin/purge URL reachable from the
   public network? (For each provider, the URL pattern differs.)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urljoin
from ..http import Client
from ..models import Finding


CDN_FINGERPRINTS = (
    ("Cloudflare",   ("cf-ray", "cf-cache-status", "server: cloudflare")),
    ("CloudFront",   ("x-amz-cf-id", "x-cache: hit from cloudfront", "via:.*cloudfront")),
    ("Bunny",        ("server: bunny", "cdn-pullzone", "cdn-cachedat")),
    ("KeyCDN",       ("server: keycdn", "x-edge-location")),
    ("Fastly",       ("x-served-by", "x-fastly-request-id")),
    ("Akamai",       ("x-akamai-transformed", "akamai-")),
)

WORKER_TEST_PATHS = ("/api/", "/api/v1/", "/admin/api/", "/__worker_health")
PURGE_URLS = (
    "/cdn-cgi/cache/purge",          # Cloudflare on-zone
    "/api/purge",                     # Bunny self-managed
    "/api/v1/cache/purge",            # KeyCDN
)


def _detect_cdn(headers: dict) -> list[str]:
    blob = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items()).lower()
    seen = []
    for name, sigs in CDN_FINGERPRINTS:
        for s in sigs:
            if re.search(s, blob):
                seen.append(name)
                break
    return list(dict.fromkeys(seen))


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    home = await client.get("/")
    if home is None:
        return [Finding(severity="info", title="CDN-edge skipped (no home)",
                        evidence="", remediation="No action.", url=target)]
    detected = _detect_cdn(home.headers or {})

    if detected:
        findings.append(Finding(
            severity="info",
            title=f"CDN(s) detected: {', '.join(detected)}",
            evidence="\n".join(f"{k}: {v}" for k, v in (home.headers or {}).items()
                                if any(s in k.lower() for s in ("cf-", "x-amz-cf", "x-fastly", "x-akamai", "server", "x-cache"))),
            remediation="No action.",
            url=target,
        ))

    # ---- #52 Cloudflare Workers route exposure ----
    if "Cloudflare" in detected:
        for path in WORKER_TEST_PATHS:
            r = await client.get(path)
            if r is None or r.status_code != 200 or not r.text:
                continue
            # If response is short JSON / has Worker-style headers, flag
            worker_marker = (
                "cf-worker" in str(r.headers).lower() or
                "cf-ray" in str(r.headers).lower() and len(r.text) < 5000
            )
            if worker_marker:
                findings.append(Finding(
                    severity="low",
                    title=f"Possible Cloudflare Worker route: {path}",
                    evidence=f"GET {path} -> 200 (len={len(r.text)}). Headers suggest Worker.",
                    remediation=("Audit the Worker source. Common bug: no auth on `/api/admin/*` "
                                 "because the Worker assumes Cloudflare Access is in front."),
                    url=target + path,
                ))

    # ---- #53 CloudFront signed-URL bypass ----
    if "CloudFront" in detected:
        # Try the home page with garbage signed-URL params — if it strips them
        # silently, the signing mechanism may not be enforced.
        r = await client.get("/?Signature=foo&Policy=bar&Key-Pair-Id=baz&Expires=99")
        if r is not None and r.status_code == 200:
            findings.append(Finding(
                severity="info",
                title="CloudFront: signed-URL params accepted on public path",
                evidence="GET /?Signature=foo... -> 200. Origin ignored bogus signature, which is normal IF the cache behaviour isn't restricted to signed URLs.",
                remediation=("If you intend `/` to be public, ignore this. If `/private/*` should be "
                             "signed-only, configure the distribution's `Trusted Signers` and verify "
                             "401/403 is returned without a valid Signature."),
                url=target,
            ))

    # ---- #54 Bunny / KeyCDN Origin-Shield ----
    if "Bunny" in detected or "KeyCDN" in detected:
        shield = "origin-shield" in str(home.headers or {}).lower()
        if not shield:
            findings.append(Finding(
                severity="info",
                title="Bunny/KeyCDN detected without Origin-Shield",
                evidence="No `origin-shield` header.",
                remediation="Enable Origin Shield in the dashboard to reduce origin load + bandwidth cost. Not a security issue but cost-affecting.",
                url=target,
            ))

    # ---- #55 Edge cache TTL ----
    cc = (home.headers or {}).get("Cache-Control", "") if home.headers else ""
    cf_cache = (home.headers or {}).get("cf-cache-status", "") if home.headers else ""
    if cc and "max-age=0" in cc.replace(" ", ""):
        findings.append(Finding(
            severity="low",
            title="Edge cache effectively disabled (Cache-Control: max-age=0)",
            evidence=f"Cache-Control: {cc}",
            remediation=("If using a CDN, set `Cache-Control: public, max-age=300, s-maxage=86400` "
                         "for HTML; long max-age for static. Otherwise edge is just a TLS terminator."),
            url=target,
        ))
    if cf_cache.lower() == "bypass":
        findings.append(Finding(
            severity="info",
            title=f"Cloudflare cache status: {cf_cache}",
            evidence=f"cf-cache-status: {cf_cache}",
            remediation="If this is unintentional, check page rules / cache levels in the Cloudflare dashboard.",
            url=target,
        ))

    # ---- #56 Origin-pull header injection ----
    step("origin: header-injection probe...")
    r = await client.get("/", headers={"X-Original-Host": "attacker.example",
                                         "X-Forwarded-Host": "attacker.example"})
    if r is not None and r.status_code == 200 and r.text:
        if "attacker.example" in r.text:
            findings.append(Finding(
                severity="high",
                title="Origin reflects X-Forwarded-Host into HTML",
                evidence=("X-Forwarded-Host: attacker.example reflected in response body. "
                          "Combined with cache poisoning, attackers can rewrite resources "
                          "to load from their domain."),
                remediation=("In nginx, never use `$http_x_forwarded_host` unless you've allow-listed "
                             "trusted upstreams. Pin `Host` from a constant on the CDN."),
                url=target,
            ))

    # ---- #57 CDN purge-API auth ----
    for path in PURGE_URLS:
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code in (200, 401, 403):
            findings.append(Finding(
                severity="medium" if r.status_code == 200 else "info",
                title=f"CDN purge endpoint reachable: {path} -> {r.status_code}",
                evidence=f"GET {path} -> {r.status_code}",
                remediation=("If 200 from anon, this is critical. Lock the purge URL to the CDN "
                             "provider's IPs or require an API key in the request."),
                url=target + path,
            ))

    return findings or [Finding(severity="info", title="CDN-edge audit — clean (no CDN detected or no issues)",
                                 evidence="", remediation="No action.", url=target)]
