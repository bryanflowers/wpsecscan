"""Favicon hash for operational intel (Shodan-compatible).

Computes the MMH3 32-bit hash of the base64-encoded favicon bytes — the same
hash Shodan uses for its `http.favicon.hash:N` query. Lets the user search
Shodan or Censys for OTHER sites with the same favicon (often: same admin's
sites, or sites in a compromised cluster).

We don't pull Shodan ourselves (would need an API key); we just compute the
hash and tell the user the search URL to paste.

mmh3 is in httpx's dependency tree on Windows, but we fall back to a pure-Python
implementation if it isn't importable.
"""
from __future__ import annotations

import base64

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

    # Convert to signed 32-bit, matching Shodan's output
    return h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1


def _shodan_b64(content: bytes) -> bytes:
    """Shodan computes the hash over base64-with-trailing-newline of the favicon
    bytes, split into 76-char lines (the historical mimetools default)."""
    b64 = base64.encodebytes(content)
    return b64  # encodebytes already adds 76-char lines + trailing \n


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching /favicon.ico for fingerprint...")
    r = await client.get("/favicon.ico")
    if r is None or r.status_code != 200 or not r.content:
        # Try /wp-content/uploads/ themes' favicon convention
        for alt in ("/favicon.png", "/wp-content/themes/twentytwentyfour/screenshot.png"):
            r2 = await client.get(alt)
            if r2 is not None and r2.status_code == 200 and r2.content:
                r = r2
                break
        else:
            findings.append(
                Finding(
                    severity="info",
                    title="No favicon fingerprint computed — /favicon.ico not reachable",
                    evidence="GET /favicon.ico did not return 200 with body content.",
                    remediation="No action.",
                    url=ctx["target"],
                )
            )
            return findings

    h = _mmh3_32(_shodan_b64(r.content))
    shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
    censys_url = f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A{h}"

    findings.append(
        Finding(
            severity="info",
            title=f"Favicon hash: {h}",
            evidence=(
                f"MurmurHash3-x86_32 of the base64-encoded /favicon.ico = {h}.\n"
                f"Find OTHER sites with the same favicon (often: same admin, same hosting cluster, "
                f"or sites compromised by the same actor):\n  Shodan: {shodan_url}\n  Censys: {censys_url}"
            ),
            remediation=(
                "Not a vulnerability by itself. Use the Shodan/Censys link as recon for related sites "
                "you own and want to add to your scan rotation. If you see compromised-looking sites "
                "with the same hash, your favicon was scraped and reused."
            ),
            url=shodan_url,
        )
    )
    return findings
