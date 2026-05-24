"""Cryptominer JS-injection detection on public pages.

Round-64 #56 — compromised WordPress sites are frequently used to host
crypto-mining JS (Coinhive, WebMiner, CryptoNight variants). The
homepage + a couple of common landing pages are scanned for the JS
fingerprints. Coinhive itself is dead since 2019, but its successors
and the same code-pattern keep cropping up in 2024+.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

_MINER_PATTERNS = (
    (re.compile(r"coinhive\.min\.js", re.IGNORECASE), "Coinhive (defunct but still injected as legacy IOC)"),
    (re.compile(r"new\s+CoinHive\.", re.IGNORECASE), "Coinhive constructor"),
    (re.compile(r"cryptonight", re.IGNORECASE), "CryptoNight (Monero) miner script"),
    (re.compile(r"webminerpool\.com", re.IGNORECASE), "WebMinerPool service"),
    (re.compile(r"mine\.torque\.net", re.IGNORECASE), "Torque mining pool"),
    (re.compile(r"jsecoin\.com", re.IGNORECASE), "JSEcoin (defunct miner-pool)"),
    (re.compile(r"minero\.cc", re.IGNORECASE), "Minero.cc"),
    (re.compile(r"hashing\.win", re.IGNORECASE), "Hashing.win miner"),
    (re.compile(r"\bWebMiner\.", re.IGNORECASE), "WebMiner library"),
    # Generic miner construction patterns
    (re.compile(r"miner\.start\(", re.IGNORECASE), "Generic miner.start() call"),
    (re.compile(r"crypto-?loot", re.IGNORECASE), "Crypto-Loot service"),
)

# A handful of pages where injected miners commonly appear (high-traffic surface)
_PROBE_PATHS = ("/", "/?utm_source=g", "/sample-page/", "/about/", "/contact/")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    seen_hits: list[tuple[str, str, str]] = []  # (path, pattern_name, snippet)
    for path in _PROBE_PATHS:
        step(f"scanning {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        for pat, name in _MINER_PATTERNS:
            m = pat.search(body)
            if m:
                snippet = body[max(0, m.start() - 40): m.end() + 40]
                seen_hits.append((path, name, snippet))

    if seen_hits:
        findings.append(
            Finding(
                severity="critical",
                title=f"Cryptominer JS pattern detected on {len({h[0] for h in seen_hits})} page(s)",
                evidence="\n".join(
                    f"  {path}: {name!r} — {snippet!r}" for path, name, snippet in seen_hits[:8]
                ),
                remediation=(
                    "This is almost always a sign of site compromise. Steps:\n"
                    "  1. Identify the injection point — grep theme + plugin PHP for `wp_enqueue_script` calls + suspicious base64.\n"
                    "  2. Check wp_options for `siteurl` / `home` tampering.\n"
                    "  3. Audit recent file modifications (`find wp-content -mtime -7`).\n"
                    "  4. Restore from a known-clean backup.\n"
                    "  5. Rotate admin passwords + WP salts."
                ),
                url=client.url(seen_hits[0][0]) if seen_hits else "",
                extra={"hits": [{"path": h[0], "miner": h[1]} for h in seen_hits]},
            )
        )

    return findings
