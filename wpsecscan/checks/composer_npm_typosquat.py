"""A34 (v2.6.0) — composer.lock / package-lock.json typosquat advisory.

When the existing `composer_lock_audit` / `yarn_pnpm_lock_audit` checks
find a reachable lock file, parse the dependency names and surface a
medium advisory for names that look like known-bad typosquats of
popular packages.

We don't ship the full typosquat dictionary (it's tens of thousands of
entries; should be a separate data file). Instead we apply a small
high-signal heuristic: any composer/npm dep name that differs from a
top-100 popular package by 1 character (Levenshtein-1) AND isn't in the
top-100 itself.
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding


# Top WP-relevant packages from packagist/npmjs (high-popularity targets)
_KNOWN_GOOD = frozenset((
    # composer
    "wpackagist-plugin/woocommerce", "wpackagist-plugin/yoast-seo",
    "wpackagist-plugin/contact-form-7", "wpackagist-plugin/elementor",
    "wpackagist-plugin/jetpack", "wpackagist-plugin/wordfence",
    "monolog/monolog", "psr/log", "symfony/console", "guzzlehttp/guzzle",
    # npm
    "react", "react-dom", "lodash", "axios", "jquery", "moment", "express",
    "webpack", "typescript", "eslint", "prettier", "vite",
))


def _levenshtein1(a: str, b: str) -> bool:
    """Cheap Levenshtein-1 test: are a and b within 1 edit?"""
    if a == b:
        return False  # we want NEAR-MATCH, not exact
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    # length differs by 1 — check insertion/deletion
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i+1:] == short:
            return True
    return False


_LOCK_PATHS = (
    "/composer.lock", "/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _LOCK_PATHS:
        step(f"lock-file typosquat scan: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        text = r.text[:200000]  # cap parse window
        # Extract candidate dep names; very lazy parse — works for all formats.
        deps = set(re.findall(r'"([a-z0-9][a-z0-9._/\@-]{2,80})"', text))

        suspicious: list[tuple[str, str]] = []
        for dep in deps:
            for good in _KNOWN_GOOD:
                if _levenshtein1(dep.lower(), good.lower()):
                    suspicious.append((dep, good))
                    break

        if suspicious:
            findings.append(Finding(
                severity="medium",
                title=f"Typosquat-candidate dependency in {path}",
                evidence=(
                    "Reachable lock file contains package names suspiciously "
                    "close to popular packages:\n  "
                    + "\n  ".join(f"{s[0]!r}  ≈  {s[1]!r}" for s in suspicious[:20])
                    + ("\n  ..." if len(suspicious) > 20 else "")
                ),
                remediation=(
                    "1. For each near-match, confirm via packagist.org /\n"
                    "   npmjs.com that the dep is legitimate.\n"
                    "2. Cross-check against socket.dev or snyk.io typosquat\n"
                    "   feed for known-malicious matches.\n"
                    "3. If suspicious, pin to a known-good package and\n"
                    "   re-install."
                ),
                url=client.url(path),
                extra={"candidates": [{"dep": d, "near": g} for d, g in suspicious]},
            ))
    return findings
