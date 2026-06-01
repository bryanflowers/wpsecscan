"""F70 (v2.8.3) — plugin slug-squatting on the WP.org repository.

When a plugin is removed from wp.org and the slug is later re-
registered under a DIFFERENT author, every WP install with that
plugin starts auto-updating to the new (potentially malicious)
author's code. This is the same supply-chain class as PyPI
typosquatting.

We cache each detected plugin's `author` field from the wp.org API
in `~/.wpsecscan/cache/wporg/`. On subsequent scans, if the author
has changed since last seen, we emit a high-severity finding.

Defensive — first run just populates the cache (no findings unless
a delta is detected).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ..http import Client
from ..models import Finding


def _cache_dir() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    d = home / "cache" / "wporg-authors"
    d.mkdir(parents=True, exist_ok=True)
    return d


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F70: probing detected plugins for author slug-squat")
    # Detected plugins live in ctx["shared"]["plugins"] (populated by the
    # plugins check earlier in the run).
    shared = ctx.get("shared") or {}
    detected = shared.get("plugins") or []
    if not detected:
        return [Finding(severity="info",
                         title="F70: no detected plugins to slug-check",
                         evidence="ctx['shared']['plugins'] empty — run after the `plugins` check.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    findings: list[Finding] = []
    checked = 0
    cache_dir = _cache_dir()
    for entry in detected[:50]:  # cap to avoid wp.org rate-limits
        # Each entry is a dict with at least a 'slug' or 'name' field
        slug = ""
        if isinstance(entry, dict):
            slug = (entry.get("slug") or entry.get("name") or "").strip().lower()
        elif isinstance(entry, str):
            slug = entry.strip().lower()
        if not slug or "/" in slug:
            continue
        # Fetch current author from wp.org
        try:
            r = await client.get(f"https://api.wordpress.org/plugins/info/1.0/{slug}.json")
        except Exception:  # noqa: BLE001
            continue
        if r is None or r.status_code != 200:
            continue
        try:
            info = r.json()
        except ValueError:
            continue
        current_author = (info.get("author") or "").strip()
        if not current_author:
            continue
        checked += 1
        cache_path = cache_dir / f"{slug}.json"
        prior_author: str | None = None
        if cache_path.exists():
            try:
                prior = json.loads(cache_path.read_text(encoding="utf-8"))
                prior_author = (prior.get("author") or "").strip() or None
            except (OSError, ValueError):
                pass
        if prior_author and prior_author != current_author:
            findings.append(Finding(
                severity="high",
                title=f"F70: plugin slug-squat candidate — `{slug}` author changed",
                evidence=(
                    f"wp.org author for `{slug}` was `{prior_author}` at last scan; "
                    f"current is `{current_author}`. This is the pattern used in real "
                    "WP supply-chain attacks (the slug is re-registered under a different "
                    "author after the original plugin is delisted)."),
                remediation=(
                    "Verify whether the change is legitimate (plugin sold, author "
                    "renamed) by checking the wp.org changelog and the plugin's "
                    "GitHub. If unverified, DEACTIVATE the plugin immediately and "
                    "manually inspect the latest update for code changes."),
                url=ctx["target"]))
        # Update cache regardless (first-run + subsequent runs)
        cache_path.write_text(json.dumps({
            "author": current_author, "checked_at": time.time()},
            indent=2), encoding="utf-8")
    if not findings:
        findings.append(Finding(
            severity="info",
            title=f"F70: slug-squat check ran on {checked} plugin(s); no author changes",
            evidence=f"Compared current wp.org `author` field against cached values for {checked} plugin(s).",
            remediation="No action needed.",
            url=ctx["target"]))
    return findings
