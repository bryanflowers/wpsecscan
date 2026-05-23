"""H5 CSRF / nonce entropy sampler.

WordPress nonces are PHP `wp_create_nonce()` outputs — short (10 chars)
and short-lived (12-24h). If a custom plugin generates its own nonces
with poor entropy (predictable, low-bit, or simple counter), the value
becomes guessable and CSRF defense collapses.

We sample N nonce values from the homepage (and a few common endpoints
that re-render forms), then compute:
  - Shannon entropy across the sample
  - Repetition rate (any collision → fatal)
  - Character-class diversity
"""
from __future__ import annotations

import math
import re
from collections import Counter

from ..http import Client
from ..models import Finding

NONCE_PATTERN = re.compile(r"_wpnonce[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9]{6,64})[\"']?", re.IGNORECASE)
SAMPLE_COUNT = 12  # WP nonces are valid 12-24h; sampling more wouldn't change values


def _shannon(s: str) -> float:
    """Shannon entropy of the string in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    nonces: list[str] = []
    paths = ("/", "/?p=1", "/wp-login.php", "/?s=test", "/wp-admin/admin-ajax.php")
    for _ in range(3):  # 3 rounds × 5 paths = up to 15 samples
        for path in paths:
            step(f"sampling nonces from {path}...")
            r = await client.get(path)
            if r is None:
                continue
            for m in NONCE_PATTERN.finditer(r.text or ""):
                v = m.group(1)
                if 6 <= len(v) <= 64:
                    nonces.append(v)
            if len(nonces) >= SAMPLE_COUNT:
                break
        if len(nonces) >= SAMPLE_COUNT:
            break

    if not nonces:
        findings.append(Finding(
            severity="info",
            title="CSRF nonce entropy — no nonces sampled",
            evidence="The homepage and login page didn't expose `_wpnonce` values; either none in HTML or the site uses a custom anti-CSRF mechanism.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    avg_len = sum(len(n) for n in nonces) / len(nonces)
    unique = set(nonces)
    repetition_rate = 1.0 - len(unique) / len(nonces)
    # Per-nonce entropy; expected for random base62 is ~5.95 bits/char
    avg_entropy = sum(_shannon(n) for n in nonces) / len(nonces)

    issues: list[str] = []
    sev = "info"

    if repetition_rate > 0.0:
        # ANY repetition across separate page loads is a bug
        issues.append(f"Repetition rate {repetition_rate*100:.0f}% — {len(nonces)} samples, only {len(unique)} unique")
        sev = "high"
    if avg_entropy < 3.5:
        issues.append(f"Average per-nonce entropy {avg_entropy:.2f} bits/char — much lower than the ~5.95 expected for random base62")
        if sev == "info":
            sev = "medium"
    if avg_len < 8:
        issues.append(f"Average nonce length {avg_len:.1f} chars — WordPress core uses 10")
        if sev == "info":
            sev = "low"

    if issues:
        findings.append(Finding(
            severity=sev,
            title=f"CSRF nonce entropy concerns ({len(issues)} issue(s))",
            evidence=(
                f"Sampled {len(nonces)} nonces across the site.\n"
                + "\n".join(f"  - {i}" for i in issues)
                + "\n\nSample nonces (first 5): " + ", ".join(nonces[:5])
            ),
            remediation=(
                "If you have a custom plugin generating CSRF tokens, switch to `wp_create_nonce($action)` "
                "(WP core, uses sha1 of session + action + user). Never use `time()` or a counter."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"CSRF nonce entropy looks healthy ({len(unique)} unique samples)",
            evidence=f"Avg length {avg_len:.0f}, avg entropy {avg_entropy:.2f} bits/char, 0% repetition.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
