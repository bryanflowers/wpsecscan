"""WP nonce freshness / rotation check.

WordPress nonces are tied to a (user, action, tick) tuple where tick is the
current 12-hour window. A fresh nonce should change every ~12 hours; a static
nonce (or one tied to nothing) is broken.

We fetch /wp-login.php twice and extract `_wpnonce` values, then a third time
after 1 second. If all three are identical, the nonce isn't tied to time and
likely isn't tied to user either — it's effectively static.
"""
from __future__ import annotations

import asyncio
import re

from ..http import Client
from ..models import Finding

NONCE_RE = re.compile(r'name=["\']_wpnonce["\'][^>]+value=["\']([a-zA-Z0-9]+)', re.IGNORECASE)


async def _extract_nonce(client: Client, path: str) -> str | None:
    r = await client.get(path)
    if r is None or not r.text:
        return None
    m = NONCE_RE.search(r.text)
    return m.group(1) if m else None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Try a few pages — different forms have different nonces
    PAGES = ("/wp-login.php?action=lostpassword", "/wp-login.php?action=register", "/wp-login.php")
    sampled: dict[str, list[str]] = {}
    for path in PAGES:
        nonces: list[str] = []
        for i in range(3):
            step(f"sampling nonce from {path} (round {i+1}/3)...")
            n = await _extract_nonce(client, path)
            if n:
                nonces.append(n)
            await asyncio.sleep(0.3)
        if nonces:
            sampled[path] = nonces

    if not sampled:
        findings.append(
            Finding(
                severity="info",
                title="No WP nonces visible to anonymous clients",
                evidence=f"Probed {len(PAGES)} pages; no `_wpnonce` field found.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    for path, nonces in sampled.items():
        unique = set(nonces)
        if len(unique) == 1 and len(nonces) >= 2:
            # All identical — could be legitimate (same 12-hour tick) but still worth noting
            findings.append(
                Finding(
                    severity="info",
                    title=f"Nonce on {path} is constant across 3 samples (expected within a 12-hour tick)",
                    evidence=f"Sampled {len(nonces)} times within 1 sec; all returned: {nonces[0][:8]}...",
                    remediation=(
                        "No action by itself — WP nonces are deliberately constant within a 12-hour window. "
                        "Re-run this scan tomorrow to verify the nonce actually rotates."
                    ),
                    url=client.url(path),
                )
            )
        elif len(unique) > 1:
            findings.append(
                Finding(
                    severity="info",
                    title=f"Nonce on {path} rotates per-request",
                    evidence="Three samples produced different values — the nonce includes a per-request element (good).",
                    remediation="No action needed.",
                    url=client.url(path),
                )
            )

    # Compare across paths: if multiple paths share the same nonce, the nonce isn't action-bound
    same_across_paths = set()
    seen_values: dict[str, str] = {}  # value -> path
    for path, nonces in sampled.items():
        if nonces:
            v = nonces[0]
            if v in seen_values and seen_values[v] != path:
                same_across_paths.add(v)
            else:
                seen_values[v] = path
    if same_across_paths:
        findings.append(
            Finding(
                severity="medium",
                title="Same nonce value reused across different actions/paths",
                evidence=(
                    "Multiple endpoints returned the same `_wpnonce`:\n"
                    + "\n".join(f"  {v[:12]}... seen on multiple paths" for v in same_across_paths)
                    + "\n\nWP nonces should bind to a specific (user, action) tuple. Same value across actions "
                    "means an attacker who acquires the nonce for one form can submit any form."
                ),
                remediation=(
                    "Make sure each form uses wp_nonce_field(<action-name>) with a UNIQUE action name. "
                    "Avoid plugins that strip nonces or use static tokens."
                ),
                url=ctx["target"],
            )
        )

    return findings
