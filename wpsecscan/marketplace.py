"""F5 Plugin / signature / payload marketplace — static + remote catalogue.

Round-56 upgrade (#22 from ZAP): in addition to the static built-in catalogue
shipped in data/marketplace.json, this module can fetch a remote catalogue
from a configurable URL (`WPSECSCAN_MARKETPLACE_URL` env, or the constant
below). Cached for 24h to ~/.wpsecscan/marketplace_cache.json.

We still deliberately do NOT auto-download or auto-install drop-ins —
security tools are prime supply-chain targets. The marketplace browser
GUI lists entries + copies the source URL; the user inspects + drops
the file into ~/.wpsecscan/{signatures,payloads,plugins}/ themselves.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

DEFAULT_REMOTE_URL = "https://raw.githubusercontent.com/bryanflowers/wpsecscan-marketplace/main/marketplace.json"
CACHE_TTL_SECONDS = 24 * 3600


def _catalogue_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "marketplace.json"
    return Path(__file__).resolve().parent / "data" / "marketplace.json"


def _remote_cache_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "marketplace_cache.json"


def _fetch_remote(url: str | None = None, timeout: float = 6.0) -> dict | None:
    """Fetch the remote catalogue. Returns None on any failure."""
    import os
    target = url or os.environ.get("WPSECSCAN_MARKETPLACE_URL") or DEFAULT_REMOTE_URL
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "WPSecScan/marketplace"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _load_remote_cached(force_refresh: bool = False) -> dict | None:
    """Read from cache file if fresh, else refresh once."""
    p = _remote_cache_path()
    now = time.time()
    if not force_refresh and p.exists():
        try:
            age = now - p.stat().st_mtime
            if age < CACHE_TTL_SECONDS:
                return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    remote = _fetch_remote()
    if remote:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(remote), encoding="utf-8")
        except OSError:
            pass
        return remote
    return None


def load_catalogue(*, include_remote: bool = True, force_refresh: bool = False) -> dict:
    """Return the merged static + remote catalogue.

    Built-in entries always present; remote entries are appended (deduped by
    `id`) so the user always has SOMETHING even if the remote is unreachable.
    """
    p = _catalogue_path()
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        d = {}
    out = {
        "categories": d.get("categories") or [],
        "entries": list(d.get("entries") or []),
    }
    if include_remote:
        remote = _load_remote_cached(force_refresh=force_refresh)
        if remote and isinstance(remote.get("entries"), list):
            existing_ids = {e.get("id") for e in out["entries"]}
            for e in remote["entries"]:
                if e.get("id") not in existing_ids:
                    out["entries"].append(e)
            for c in remote.get("categories", []) or []:
                if c not in out["categories"]:
                    out["categories"].append(c)
    return out


def entries_by_category(category: str | None = None) -> list[dict]:
    """Filter the catalogue by category. None returns everything."""
    cat = load_catalogue()
    if not category:
        return list(cat.get("entries", []))
    return [e for e in cat.get("entries", []) if e.get("category") == category]
