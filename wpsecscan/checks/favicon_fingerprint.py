"""Favicon-fingerprint check.

Hash the favicon and report it. Useful for two reasons:
  1. Threat-intel feeds (Shodan, Censys) index sites by favicon hash —
     yours being indexable means it's findable by attackers searching for
     specific stacks.
  2. Default-favicon collisions tell you the site is "stock" (no branding
     in place), which often correlates with overall security posture.
"""
from __future__ import annotations

import hashlib
import codecs

from ..http import Client
from ..models import Finding

# Some common stock favicon hashes (MurmurHash3 used by Shodan, MD5 listed here for portability)
KNOWN_STOCK_FAVICONS_MD5 = {
    # WordPress default — there isn't really one shared across themes, but
    # the listing format here lets us flag additional well-known hashes.
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching /favicon.ico...")
    r = await client.get("/favicon.ico")
    if r is None or r.status_code != 200 or not r.content:
        findings.append(
            Finding(
                severity="info",
                title="No /favicon.ico served (or empty)",
                evidence=f"GET /favicon.ico -> {r.status_code if r else 'no response'}",
                remediation="No action needed unless you intend to serve a favicon.",
                url=client.url("/favicon.ico"),
            )
        )
        return findings

    content = r.content
    md5 = hashlib.md5(content).hexdigest()  # noqa: S324 — fingerprint not security
    sha1 = hashlib.sha1(content).hexdigest()  # noqa: S324
    # Shodan/Censys use a base64+mmh3 style; we emit base64-encoded content length as a proxy
    b64 = codecs.encode(content, "base64").decode().strip()
    findings.append(
        Finding(
            severity="info",
            title=f"Favicon fingerprint (size={len(content)} bytes, md5={md5[:12]})",
            evidence=(
                f"MD5:  {md5}\n"
                f"SHA1: {sha1}\n"
                f"Size: {len(content)} bytes\n"
                f"Base64 length: {len(b64)} chars\n\n"
                "Hash this against Shodan / Censys (`http.favicon.hash:` filter) to see which sites share your favicon. "
                "Identical favicons across many WP installs often means stock theme + minimal branding."
            ),
            remediation=(
                "If you'd rather not be indexed by favicon: serve a unique favicon per site, "
                "or set a 404 on /favicon.ico to avoid the hash entirely."
            ),
            url=client.url("/favicon.ico"),
            extra={"md5": md5, "sha1": sha1, "size": len(content)},
        )
    )
    return findings
