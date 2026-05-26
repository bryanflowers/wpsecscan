"""Favicon fingerprinting — MD5/SHA1 plus the Shodan-compatible MMH3 hash.

Hash the favicon and report it. Useful for two reasons:
  1. Threat-intel feeds (Shodan, Censys) index sites by favicon hash —
     yours being indexable means it's findable by attackers searching for
     specific stacks.
  2. Default-favicon collisions tell you the site is "stock" (no branding
     in place), which often correlates with overall security posture.

One fetch, all the hashes — both MMH3 (Shodan/Censys lookups) and MD5/SHA1
(operational fingerprint).
"""
from __future__ import annotations

import base64
import codecs
import hashlib

from ..http import Client
from ..models import Finding


def _mmh3_32(key: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32. Mirrors the C reference implementation
    and matches the SIGNED-32-bit value Shodan expects."""
    length = len(key)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for i in range(nblocks):
        k1 = int.from_bytes(key[i * 4: i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = key[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1


def _shodan_b64(content: bytes) -> bytes:
    """Shodan computes the hash over base64-with-trailing-newline of the favicon
    bytes, split into 76-char lines (the historical mimetools default)."""
    return base64.encodebytes(content)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching /favicon.ico...")
    r = await client.get("/favicon.ico")
    if r is None or r.status_code != 200 or not r.content:
        # Fall back to a couple of alternate locations before giving up.
        for alt in ("/favicon.png", "/wp-content/themes/twentytwentyfour/screenshot.png"):
            r2 = await client.get(alt)
            if r2 is not None and r2.status_code == 200 and r2.content:
                r = r2
                break
        else:
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
    md5 = hashlib.md5(content).hexdigest()  # noqa: S324 — fingerprint, not security
    sha1 = hashlib.sha1(content).hexdigest()  # noqa: S324
    mmh3 = _mmh3_32(_shodan_b64(content))
    b64_len = len(codecs.encode(content, "base64").decode().strip())

    shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}"
    censys_url = f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A{mmh3}"

    findings.append(
        Finding(
            severity="info",
            title=f"Favicon fingerprint (mmh3={mmh3}, md5={md5[:12]}, {len(content)} B)",
            evidence=(
                f"MMH3 (Shodan/Censys): {mmh3}\n"
                f"MD5:  {md5}\n"
                f"SHA1: {sha1}\n"
                f"Size: {len(content)} bytes (base64 length: {b64_len} chars)\n\n"
                f"Find OTHER sites with the same favicon (often: same admin, same hosting "
                f"cluster, or sites compromised by the same actor):\n"
                f"  Shodan: {shodan_url}\n"
                f"  Censys: {censys_url}"
            ),
            remediation=(
                "Not a vulnerability by itself. If you'd rather not be indexed by favicon: "
                "serve a unique favicon per site, or 404 on /favicon.ico. If you see "
                "compromised-looking sites sharing your hash, your favicon was scraped and reused."
            ),
            url=client.url("/favicon.ico"),
            extra={"md5": md5, "sha1": sha1, "mmh3": mmh3, "size": len(content)},
        )
    )
    return findings
