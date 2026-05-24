"""Scan a Wayback Machine snapshot of a site.

Round-64 #171 — useful for incident response ("what was on the site
when the attacker landed?") or for auditing a site you're acquiring.
"""
from __future__ import annotations

import httpx
from urllib.parse import quote


WAYBACK_AVAILABLE = "https://archive.org/wayback/available"
WAYBACK_HOST = "https://web.archive.org"


async def find_snapshot(target: str, *, timestamp: str | None = None) -> dict | None:
    """Query the Wayback Availability API.

    timestamp: YYYYMMDD or YYYYMMDDhhmmss. If None, returns the closest
    snapshot to the most recent.
    """
    params = {"url": target}
    if timestamp:
        params["timestamp"] = timestamp
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(WAYBACK_AVAILABLE, params=params)
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            return None
        archived = data.get("archived_snapshots", {}).get("closest")
        if not archived:
            return None
        return {
            "url":       archived.get("url"),
            "timestamp": archived.get("timestamp"),
            "available": archived.get("available", False),
        }


def wayback_url(target: str, timestamp: str) -> str:
    """Return the Wayback playback URL for a timestamp."""
    return f"{WAYBACK_HOST}/web/{timestamp}/{target}"


def wayback_replay_base(target: str, timestamp: str) -> str:
    """Base URL to use as client.base_url for scanning the snapshot."""
    return f"{WAYBACK_HOST}/web/{timestamp}id_/{target}"


# Note: not all WPSecScan checks are meaningful against a Wayback
# replay (the Wayback host adds headers + rewrites links). Restrict
# to passive content-scan checks for best results.
HISTORICAL_SAFE_CHECKS = (
    "core_version",      # version often visible in HTML
    "plugins",           # plugin slugs in HTML
    "secret_leak",       # accidental leaks in source
    "js_libraries",      # library versions in scripts
    "mixed_content",     # http:// inside HTML
    "favicon_fingerprint",
    "users",             # author= patterns in HTML
)
