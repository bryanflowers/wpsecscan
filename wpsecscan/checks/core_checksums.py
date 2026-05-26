"""WP core integrity via official wp.org checksums.

The existing core_tampering check uses pattern heuristics. This one is
authoritative: it downloads the official SHA-256 manifest from wp.org
for the detected core version and probes a small set of high-impact
core files via the public web tree (/wp-includes/version.php,
/wp-includes/load.php, etc.). Any file that returns 200 with a non-
matching SHA-256 = critical (webshell or backdoor in a core file).
"""
from __future__ import annotations
import hashlib
import os
import re

import httpx

from ..http import Client
from ..models import Finding


# Files always present in core that are likely to be probable via the
# web tree on a default WP install. NOT exhaustive — this is a fast
# trip-wire, not a full audit. Use the companion plugin or wp-cli for
# the full thousand-file audit.
_PROBE_FILES = (
    "/wp-includes/version.php",
    "/wp-includes/load.php",
    "/wp-includes/functions.php",
    "/wp-admin/install.php",
    "/wp-login.php",
)


async def _fetch_checksums(version: str) -> dict[str, str] | None:
    """Returns {path: sha256-hex} for the given WP version, or None on error."""
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    url = f"https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US"
    try:
        async with httpx.AsyncClient(timeout=15.0,
                                     headers={"User-Agent": "WPSecScan/checksums"}) as c:
            r = await c.get(url)
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data.get("checksums") or None


def _looks_like_php_source(text: str) -> bool:
    return "<?php" in text[:200] or "phpinfo" in text or "WP_Hook" in text


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    wp_version = (ctx.get("shared", {}).get("wp_version") or "").strip()
    if not wp_version:
        return findings
    step(f"fetching wp.org checksums for core {wp_version}...")
    checksums = await _fetch_checksums(wp_version)
    if not checksums:
        return findings
    mismatches: list[tuple[str, str, str]] = []  # (path, got, expected)
    for path in _PROBE_FILES:
        # checksums keys are like "wp-includes/version.php" — strip leading /
        key = path.lstrip("/")
        expected = checksums.get(key)
        if not expected:
            continue
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.content:
            continue
        body = r.content
        # If we got HTML back (no .php source served), skip — we can't compare.
        if not _looks_like_php_source(r.text or ""):
            continue
        got = hashlib.sha256(body).hexdigest()
        if got != expected:
            mismatches.append((path, got, expected))
    if not mismatches:
        return findings
    lines = "\n".join(
        f"  {p}\n      got:      {got}\n      expected: {exp}"
        for p, got, exp in mismatches
    )
    findings.append(Finding(
        severity="critical",
        title=f"WP core file checksum mismatch ({len(mismatches)} file(s) modified)",
        evidence=(
            f"For WordPress {wp_version}, these core files don't match the official "
            f"wp.org SHA-256:\n{lines}\n\n"
            "A core-file checksum mismatch is one of the strongest indicators "
            "of compromise — backdoors, webshells, and credential-stealers are "
            "frequently planted in wp-includes/load.php or wp-includes/version.php. "
            "This finding is authoritative: the checksum source is wp.org itself, "
            "not a heuristic."
        ),
        remediation=(
            "1. STOP scheduled jobs and active editing on the site immediately — "
            "treat as an active incident.\n"
            "2. Diff the modified file against the official version: "
            f"`wp core verify-checksums --version={wp_version}` (via wp-cli) "
            "or download the upstream file from "
            "https://github.com/WordPress/WordPress/tree/{wp_version} for "
            "comparison.\n"
            "3. Once the modification is understood, restore from a known-good "
            "backup taken before the suspected compromise. Rotate all secrets "
            "(DB password, WP salts, plugin API keys).\n"
            "4. Audit access logs to find the entry point — most core-file "
            "tampering is downstream of either a vulnerable plugin or a "
            "compromised admin account."
        ),
        url=ctx["target"],
        extra={"mismatches": [{"path": p, "got": g, "expected": e}
                              for p, g, e in mismatches]},
    ))
    return findings
