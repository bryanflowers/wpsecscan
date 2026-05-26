"""Abandoned-plugin detector — flags plugins that haven't been updated in
years, BEFORE they pick up a CVE.

Cross-references each enumerated plugin slug against the WordPress.org
plugin info endpoint and reports `last_updated`. The thresholds:
  - >2 years stale  -> medium  "long-stale plugin (no CVE yet)"
  - >4 years stale  -> high    "abandoned plugin (no security maintenance)"
  - removed from wp.org -> high "delisted plugin (can't receive updates)"

This is orthogonal to plugin_cves: a plugin can be CVE-free today but
unmaintained, which is itself a forward-looking risk indicator. The
opposite is also true — a plugin with recent updates but a known CVE
already gets flagged by plugin_cves; the cemetery check stays quiet
there to avoid double-reporting.

Network: one GET per discovered plugin against
https://api.wordpress.org/plugins/info/1.0/{slug}.json (cached 24h
on disk under ~/.wpsecscan/cache/wporg/).
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..http import Client
from ..models import Finding

_WPORG = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
_CACHE_TTL = 24 * 3600  # 24 hours


def _cache_dir() -> Path:
    import os as _os
    home = Path(_os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    p = home / "cache" / "wporg"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _fetch_wporg_sync(slug: str, timeout: float = 8.0) -> dict | None:
    """Synchronous wp.org fetch. Returns a parsed JSON dict, or None on
    failure / 404 (delisted). Result is sentinel-coded: {"_delisted": True}
    when wp.org 404s the slug. Called via asyncio.to_thread from the async
    check() so it doesn't block the event loop."""
    cache_path = _cache_dir() / f"{slug}.json"
    if cache_path.exists():
        try:
            age = time.time() - cache_path.stat().st_mtime
            if age < _CACHE_TTL:
                return json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    try:
        with httpx.Client(timeout=timeout,
                          headers={"User-Agent": "WPSecScan/cemetery"}) as c:
            r = c.get(_WPORG.format(slug=slug))
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code == 404:
        data = {"_delisted": True}
    elif r.status_code != 200:
        return None
    else:
        try:
            data = r.json()
        except ValueError:
            return None
        # wp.org returns `false` (literal JSON) when the slug doesn't exist —
        # we treat that the same as 404.
        if data is False or data is None:
            data = {"_delisted": True}
    try:
        cache_path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
    return data


async def _fetch_wporg(slug: str, timeout: float = 8.0) -> dict | None:
    """Async wrapper around the synchronous wp.org fetch — runs in a thread
    so a slow wp.org response doesn't block the entire scan's event loop
    (which would freeze every other concurrent check for up to 8 s each)."""
    return await asyncio.to_thread(_fetch_wporg_sync, slug, timeout)


def _years_since(iso_or_date_str: str) -> float | None:
    """Parse '2022-08-14 11:34am GMT' (wp.org's quirky format) or ISO.

    wp.org uses lowercase am/pm, and on Linux strptime's %p only matches
    uppercase — so we uppercase the string and strip the GMT suffix before
    trying time-of-day formats. Without this, every wp.org last_updated
    string silently failed to parse on Linux runners.
    """
    if not iso_or_date_str:
        return None
    s = iso_or_date_str.strip()
    # Strip trailing " GMT" so strptime doesn't have to match it literally.
    if s.upper().endswith(" GMT"):
        s = s[:-4].strip()
    upper = s.upper()
    for fmt in ("%Y-%m-%d %I:%M%p", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(upper, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - dt
            return delta.total_seconds() / (365.25 * 86400)
        except ValueError:
            continue
    return None


def _format_installs(v) -> str:
    """wp.org sometimes returns int (e.g. 50000) and sometimes string ('1+'
    for plugins with < ~10 installs). The :, format spec crashes on strings,
    so coerce to int when possible and fall back to a safe display string."""
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, str) and v.rstrip("+").isdigit():
        return v
    return str(v) if v else "?"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    plugins: dict = ctx.get("shared", {}).get("plugins") or {}
    if not plugins:
        findings.append(Finding(
            severity="info",
            title="Plugin cemetery check skipped — no plugins enumerated",
            evidence="Nothing in ctx['shared']['plugins']; the plugins check found nothing.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Skip plugins that already have a CVE finding — avoid double-reporting.
    # plugin_cves stashes matched slugs in ctx['shared']['cve_matched_slugs'].
    cve_matched = set((ctx.get("shared", {}).get("cve_matched_slugs") or set()))

    for slug in plugins:
        if slug in cve_matched:
            continue
        step(f"checking wp.org maintenance status of {slug}...")
        data = await _fetch_wporg(slug)
        if data is None:
            continue
        if data.get("_delisted"):
            findings.append(Finding(
                severity="high",
                title=f"Plugin '{slug}' delisted from wp.org — cannot receive updates",
                evidence=(
                    f"https://api.wordpress.org/plugins/info/1.0/{slug}.json -> 404.\n"
                    "Plugins are typically delisted because of an unpatched security "
                    "issue or developer abandonment. The site cannot auto-update this "
                    "plugin and won't be notified of new vulnerabilities."
                ),
                remediation=(
                    f"Replace `{slug}` with an actively-maintained alternative or "
                    "remove it from the site. Verify on https://wordpress.org/plugins/ "
                    "search — if the listing is gone, do not reinstall."
                ),
                url=f"https://wordpress.org/plugins/{slug}/",
                extra={"slug": slug, "wporg_status": "delisted"},
            ))
            continue
        years = _years_since(data.get("last_updated", ""))
        if years is None:
            continue
        if years >= 4:
            sev = "high"
            label = f"Plugin '{slug}' abandoned — no update in ~{years:.1f} years"
        elif years >= 2:
            sev = "medium"
            label = f"Plugin '{slug}' long-stale — no update in ~{years:.1f} years"
        else:
            continue
        findings.append(Finding(
            severity=sev,
            title=label,
            evidence=(
                f"wp.org last_updated: {data.get('last_updated', '?')}\n"
                f"Active installs: {_format_installs(data.get('active_installs'))}\n"
                f"Tested up to WP: {data.get('tested', '?')}\n"
                f"Requires WP: {data.get('requires', '?')}\n\n"
                "Unmaintained plugins accumulate undisclosed vulnerabilities and stop "
                "tracking newer WP-core security model changes. The risk grows with time."
            ),
            remediation=(
                "Audit whether the plugin is still doing useful work. If yes, find a "
                "maintained replacement (search wp.org for newer alternatives) or move "
                "the functionality to your own theme code. If no, deactivate + delete."
            ),
            url=f"https://wordpress.org/plugins/{slug}/",
            extra={"slug": slug, "years_since_update": round(years, 1),
                   "active_installs": data.get("active_installs"),
                   "tested": data.get("tested")},
        ))

    if not findings:
        findings.append(Finding(
            severity="info",
            title="No abandoned or delisted plugins detected",
            evidence=f"Checked {len(plugins)} enumerated plugin(s); all have recent wp.org activity.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
