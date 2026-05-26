"""Detect an HTTP-hop in the redirect chain to /wp-login.php.

Even a single http:// hop in the redirect chain means login credentials
can travel in plaintext for one network hop — sufficient for a
man-in-the-middle on the same network to capture credentials. This is
distinct from a missing-HTTPS finding because the FINAL URL is HTTPS;
only the intermediate hop is broken.
"""
from __future__ import annotations
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    # We need to follow redirects manually to inspect each hop's scheme.
    # The pooled Client may or may not be HTTPS-bound depending on the target
    # scheme, so use httpx.AsyncClient directly with follow_redirects=False.
    target_origin = ctx["target"].rstrip("/")
    login_url = target_origin + "/wp-login.php"
    step(f"following redirect chain from {login_url}...")
    chain: list[str] = [login_url]
    schemes: list[str] = [urlparse(login_url).scheme]
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False,
                                     verify=False) as c:
            current = login_url
            for hop in range(5):
                r = await c.get(current)
                if r.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = r.headers.get("location")
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = f"{urlparse(current).scheme}://{urlparse(current).hostname}{loc}"
                chain.append(loc)
                schemes.append(urlparse(loc).scheme)
                current = loc
    except (httpx.HTTPError, OSError):
        return findings
    if len(chain) < 2:
        return findings
    # Did we land at an HTTPS endpoint but pass through HTTP somewhere?
    final = schemes[-1]
    has_http_hop = any(s == "http" for s in schemes[:-1])
    if not has_http_hop or final != "https":
        return findings
    findings.append(Finding(
        severity="high",
        title=f"Login redirect chain ({len(chain)} hops) includes an http:// hop",
        evidence=(
            "Redirect chain from /wp-login.php:\n"
            + "\n".join(f"  {i+1}. {url}" for i, url in enumerate(chain))
            + "\n\nEven though the FINAL destination is HTTPS, credentials POSTed "
              "into the login flow travel through an http:// intermediate, which a "
              "MITM on the local network can capture in plaintext. Browsers do "
              "show the green padlock on the final page, masking this issue."
        ),
        remediation=(
            "1. Make sure /wp-login.php (and /wp-admin) redirect DIRECTLY to "
            "their HTTPS counterparts — never via an http:// hop.\n"
            "2. In wp-config.php: `define('FORCE_SSL_ADMIN', true);` (already "
            "default-on in recent WP versions, but verify).\n"
            "3. Audit the web-server config for an `http → https` redirect that "
            "loses the /wp-login.php path along the way. Common bug: 301 to "
            "https://www.example.com/ (without preserving the path)."
        ),
        url=login_url,
        extra={"redirect_chain": chain},
    ))
    return findings
