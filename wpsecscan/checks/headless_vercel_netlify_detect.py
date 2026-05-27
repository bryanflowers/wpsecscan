"""N138 (v2.7.0) — Headless WP on Vercel / Netlify detection.

When the WP REST API is reachable directly on a public WordPress host
but the frontend is served from Vercel/Netlify, the operator typically
forgets to either:
  (a) block direct access to wp-json/ on the WP host, or
  (b) put the WP host behind HTTP Basic Auth.

This check fingerprints the front-end deployment platform from response
headers + flags any reachable /wp-json/ on a HOST whose front-end is
Vercel/Netlify/etc.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("headless probe: GET /")
    home = await client.get("/")
    if home is None:
        return findings

    # Front-end platform fingerprint via headers
    platform = ""
    server = home.headers.get("server", "").lower()
    x_vercel = home.headers.get("x-vercel-id", "")
    x_nf = home.headers.get("x-nf-request-id", "") or home.headers.get("x-netlify-version", "")
    x_cf_pages = home.headers.get("cf-pages", "") or home.headers.get("x-cf-pages", "")
    if x_vercel: platform = "Vercel"
    elif x_nf:    platform = "Netlify"
    elif x_cf_pages: platform = "Cloudflare Pages"
    elif "vercel" in server: platform = "Vercel"
    elif "netlify" in server: platform = "Netlify"

    if not platform:
        return findings

    # Now check if the REST API is reachable from this same host
    step(f"headless ({platform}): wp-json probe")
    rest = await client.get("/wp-json/")
    if rest is None or rest.status_code != 200:
        return findings

    findings.append(Finding(
        severity="medium",
        title=f"Headless WP detected ({platform}) — REST API reachable from the public host",
        evidence=(
            f"Front-end platform fingerprint: {platform}\n"
            f"  (via headers: x-vercel-id={x_vercel!r}, "
            f"x-nf-request-id={x_nf!r}, server={server!r})\n"
            f"GET /wp-json/ returns HTTP 200 — the WordPress REST API is "
            f"directly accessible. In a headless setup the WP host typically "
            f"should NOT serve REST to anonymous visitors."
        ),
        remediation=(
            "1. If your headless frontend fetches from a SEPARATE WP host "
            "(e.g. wp.example.com), put that host behind HTTP Basic Auth or "
            "an IP allow-list so only your build server can reach REST.\n"
            "2. If the frontend uses preview-mode draft fetching, gate that "
            "with Vercel Edge Middleware or Netlify Edge Functions checking "
            "an HMAC-signed preview token.\n"
            "3. Confirm /wp-json/wp/v2/users isn't returning user enumeration."
        ),
        url=client.url("/wp-json/"),
        extra={"platform": platform},
    ))
    return findings
