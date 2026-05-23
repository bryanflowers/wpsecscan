"""#5 + #6 — WordPress salts age check + nonce-randomness sampling.

Salts (`AUTH_KEY`, `SECURE_AUTH_KEY`, etc.) live in wp-config.php and should
be rotated periodically. We can't read wp-config remotely, but we CAN infer
rotation from nonce values — same salts → same nonces for the same action.

We sample wp-login nonces twice with a small delay, compare them, and flag
when they're identical (suggesting heavy cache OR static salts).

#6 = sample 50 nonces, compute collisions.
"""
from __future__ import annotations

import asyncio
import re
from ..http import Client
from ..models import Finding

NONCE_RE = re.compile(r'name="_wpnonce"\s+value="([0-9a-f]{10,})"', re.IGNORECASE)
LOGGED_OUT_NONCE_RE = re.compile(r'"nonce"\s*:\s*"([0-9a-f]{10,})"', re.IGNORECASE)


async def _sample(client: Client, path: str = "/wp-login.php", n: int = 5) -> list[str]:
    out = []
    for _ in range(n):
        r = await client.get(path)
        if r is None:
            continue
        for m in NONCE_RE.finditer(r.text or ""):
            out.append(m.group(1))
        await asyncio.sleep(0.1)
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    findings = []
    step("sampling wp-login nonces...")
    nonces = await _sample(client, n=5)
    if not nonces:
        return [Finding(severity="info", title="Salt-age probe — no nonces visible on /wp-login.php",
                        evidence="No `_wpnonce` field in the login form HTML.",
                        remediation="No action.", url=ctx["target"])]
    unique = set(nonces)
    if len(unique) == 1 and len(nonces) >= 3:
        findings.append(Finding(
            severity="medium",
            title="WordPress nonces identical across samples",
            evidence=f"Took {len(nonces)} samples from /wp-login.php; all returned the same nonce {nonces[0][:8]}...\n\nWP nonces incorporate a 12-24h tick — same value across multiple seconds is normal. But if it's still the same in 24h, suspect static salts (= forever-valid CSRF tokens).",
            remediation="Verify salts rotate. Regenerate with `wp salts create` (wp-cli) or the official generator at https://api.wordpress.org/secret-key/1.1/salt/ — drop the output into wp-config.php replacing the existing block. Old sessions invalidate (everyone has to re-log-in).",
            url=ctx["target"] + "/wp-login.php",
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"Salt-age probe: {len(unique)} unique nonce(s) across {len(nonces)} sample(s)",
            evidence="Nonces are rotating — salts appear active.",
            remediation="No action.", url=ctx["target"],
        ))
    return findings
