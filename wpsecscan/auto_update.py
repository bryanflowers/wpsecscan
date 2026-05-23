"""J19 Auto-update channel.

Reads the latest release tag from GitHub's `/releases/latest` API and
compares it against the embedded `__version__`. If newer, prints a one-line
notice on scanner startup and exposes the download URL.

Does NOT auto-download — security tools should never silently replace
themselves. The user gets a notice and decides.

Three channels:
  - stable  (default): only `vN.M.K` releases (no pre-release tags)
  - daily            : nightly tag matching `nightly-*`
  - edge             : pre-releases (`vN.M.K-rcX`)
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = "bryanflowers/wpsecscan"  # change if you fork — must match the GitHub repo path
CHECK_INTERVAL_HOURS = 24
USER_AGENT = "WPSecScan/auto_update"


def _cache_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "update_check.json"


def _save_cache(data: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _fetch_latest(channel: str = "stable", *, timeout: float = 4.0) -> dict | None:
    """Query GitHub for the latest release on the given channel."""
    url = f"https://api.github.com/repos/{REPO}/releases"
    if channel == "stable":
        url += "/latest"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError):
        return None

    if isinstance(data, list):
        # /releases returns an array; filter by channel
        for entry in data:
            tag = entry.get("tag_name", "")
            if channel == "daily" and tag.startswith("nightly-"):
                return entry
            if channel == "edge" and ("-rc" in tag or entry.get("prerelease")):
                return entry
        return None
    return data


def check_for_update(current_version: str, channel: str = "stable",
                     *, force: bool = False) -> dict | None:
    """Return release dict if a newer version is available, else None.

    Caches the check for CHECK_INTERVAL_HOURS so the scan startup isn't
    blocked on the GitHub API for every invocation.
    """
    cache = _load_cache()
    cache_age_h = None
    if cache.get("checked_at"):
        try:
            checked = datetime.fromisoformat(cache["checked_at"].replace("Z", "+00:00"))
            cache_age_h = (datetime.now(timezone.utc) - checked).total_seconds() / 3600
        except (ValueError, AttributeError):
            cache_age_h = None
    if not force and cache_age_h is not None and cache_age_h < CHECK_INTERVAL_HOURS:
        latest_tag = cache.get("latest_tag", "")
        if latest_tag and latest_tag != f"v{current_version}":
            return cache.get("payload")
        return None

    payload = _fetch_latest(channel)
    if not payload:
        return None
    latest_tag = payload.get("tag_name", "")
    _save_cache({
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "latest_tag": latest_tag,
        "payload": {
            "tag_name": latest_tag,
            "html_url": payload.get("html_url", ""),
            "published_at": payload.get("published_at", ""),
        },
    })
    if latest_tag and latest_tag != f"v{current_version}":
        return payload
    return None


def notice(current_version: str, channel: str = "stable") -> str | None:
    """One-line user-facing notice, or None if no update is available."""
    rel = check_for_update(current_version, channel)
    if not rel:
        return None
    tag = rel.get("tag_name", "")
    url = rel.get("html_url", "")
    try:
        from . import activity as _act
        _act.emit("meta", f"update available: {tag} (you're on v{current_version})")
    except ImportError:
        pass
    return f"WPSecScan {tag} is available (you're on v{current_version}). Download: {url}"
