"""Sucuri SiteCheck integration — scrape the free public scan result.

No API key required. We fetch sitecheck.sucuri.net/results/<url> and extract
the high-level verdict (malware / blacklisted / outdated / clean). Cached
for 1 hour per URL.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

SITECHECK_URL = "https://sitecheck.sucuri.net/api/v3/?scan="
CACHE_TTL_SECONDS = 3600  # 1 hour


def _cache_path() -> Path:
    from .. import history as _h
    return Path(_h._home()) / "sucuri_cache.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(d: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(d, indent=2), encoding="utf-8")
    except OSError:
        pass


def lookup(target: str) -> dict | None:
    """Return {malware_found, blacklisted, software_outdated, raw, permalink} or None."""
    cache = _load_cache()
    now = time.time()
    entry = cache.get(target)
    if entry and (now - entry.get("ts", 0) < CACHE_TTL_SECONDS):
        return {k: v for k, v in entry.items() if k != "ts"}

    url = SITECHECK_URL + urllib.parse.quote(target, safe="")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/sucuri"})
        with urllib.request.urlopen(req, timeout=15.0) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None

    # Parse the JSON. Sucuri's structure: { "scan": {...}, "blacklists": [...], "warnings": [...] }
    scan = data.get("scan") or {}
    blacklists = data.get("blacklists") or []
    warnings = data.get("warnings") or []
    outdated = []
    for w in warnings:
        wstr = str(w).lower()
        if "outdated" in wstr or "out-of-date" in wstr:
            outdated.append(str(w))

    result = {
        "malware_found": bool(data.get("malware")),
        "blacklisted": [str(bl.get("name", "?")) for bl in blacklists if isinstance(bl, dict)],
        "software_outdated": outdated,
        "site": scan.get("site", target),
        "permalink": f"https://sitecheck.sucuri.net/results/{urllib.parse.quote(target, safe='')}",
    }
    cache[target] = {**result, "ts": now}
    _save_cache(cache)
    try:
        from .. import activity as _act
        verdict = "malware" if result["malware_found"] else ("blacklisted" if result["blacklisted"] else "clean")
        _act.emit("threat_intel", f"Sucuri SiteCheck: {verdict}")
    except ImportError:
        pass
    return result
