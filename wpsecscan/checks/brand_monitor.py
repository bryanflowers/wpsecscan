"""Brand-monitor — flag typosquats of your domain.

Round-64 #170 — given the target domain `example.com`, generate
common typosquat permutations (`exampie.com`, `examp1e.com`,
`xn--exmple-...` etc.) and check whether they exist via DNS.

Limited to a curated permutation set to keep query count low. Skips
in CI / WPSECSCAN_NO_NETWORK mode.
"""
from __future__ import annotations

import asyncio
import os
import socket
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


# Common visual-substitution rules: pick one char in the domain
# and swap it. Returns up to 12 candidates from a single domain.
_SWAPS = (
    ("o", "0"),
    ("l", "1"),
    ("i", "1"),
    ("e", "3"),
    ("a", "@"),
    ("s", "5"),
)


def _typosquats(domain: str) -> list[str]:
    """Return a small bounded list of likely typosquats."""
    if "." not in domain:
        return []
    name, _, tld = domain.partition(".")
    out: list[str] = []
    # Character swaps
    for src, dst in _SWAPS:
        if src in name:
            out.append(name.replace(src, dst, 1) + "." + tld)
    # Adjacent-key swaps (qwerty layout, neighbours)
    qw_neighbours = {
        "a": "sq", "s": "ad", "d": "sf", "f": "dg",
        "q": "wa", "w": "qe", "e": "wr", "r": "et",
        "z": "xa", "x": "zc", "c": "xv", "v": "cb",
    }
    if name:
        first = name[0]
        for n in qw_neighbours.get(first, ""):
            out.append(n + name[1:] + "." + tld)
    # Doubled-char (e.g. "exxample.com")
    if len(name) >= 3:
        out.append(name[:2] + name[1] + name[1:] + "." + tld)
    # Drop-char
    if len(name) >= 4:
        out.append(name[1:] + "." + tld)
    # De-dupe + cap
    seen = set()
    final = []
    for d in out:
        if d != domain and d not in seen:
            seen.add(d)
            final.append(d)
        if len(final) >= 10:
            break
    return final


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return findings

    target = client.base_url
    host = urlparse(target if target.startswith("http") else f"http://{target}").hostname or ""
    # Strip www. for the canonical name
    bare = host.removeprefix("www.")
    candidates = _typosquats(bare)
    if not candidates:
        return findings

    step(f"checking {len(candidates)} typosquat candidates for {bare}...")
    loop = asyncio.get_event_loop()

    async def _exists(d: str) -> tuple[str, bool]:
        try:
            await loop.run_in_executor(None, socket.gethostbyname, d)
            return d, True
        except (socket.gaierror, OSError):
            return d, False

    results = await asyncio.gather(*( _exists(d) for d in candidates ), return_exceptions=False)
    registered = [d for d, ok in results if ok]
    if registered:
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(registered)} typosquat domain(s) registered against {bare}",
                evidence=f"Registered typosquats: {', '.join(registered[:10])}",
                remediation=(
                    "Investigate each typosquat. If it hosts a phishing or copycat of your site:\n"
                    "  - File a UDRP complaint at WIPO\n"
                    "  - Notify your hosting + registrar\n"
                    "  - Add SPF/DMARC strict on your domain to reduce email-spoof risk\n"
                    "Prophylactically: register the 5-10 most-obvious typosquats yourself + redirect to your real domain."
                ),
                url=client.url("/"),
                extra={"typosquats": registered},
            )
        )

    return findings
