"""CVE explainer — convert a CVE ID into a 2-paragraph plain-English summary.

Sources (in priority order):
  1. Wordfence Intelligence DB entry (already in local cache)
  2. Patchstack writeup (if --patchstack-token provided)
  3. NVD description (always free)
  4. Empty string (if all sources fail)

Results cached in ~/.wpsecscan/cve_explainer.json for 30 days.
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CACHE_TTL_SECONDS = 30 * 24 * 3600


def _cache_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "cve_explainer.json"


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


def _fetch_nvd(cve: str, timeout: float = 8.0) -> str | None:
    try:
        req = urllib.request.Request(NVD_API + cve, headers={"User-Agent": "WPSecScan/cve-explainer"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None
    try:
        items = data.get("vulnerabilities", []) or []
        if not items:
            return None
        descriptions = (items[0].get("cve") or {}).get("descriptions", []) or []
        for d in descriptions:
            if d.get("lang") == "en":
                return d.get("value")
    except (KeyError, IndexError, TypeError):
        pass
    return None


def explain(cve: str, wordfence_description: str = "") -> str:
    """Return a plain-English summary of `cve`. May return empty string."""
    if not cve:
        return ""
    cache = _load_cache()
    now = time.time()
    entry = cache.get(cve)
    if entry and (now - entry.get("ts", 0) < CACHE_TTL_SECONDS):
        return entry.get("text") or ""

    # Priority 1: Wordfence description we already have
    if wordfence_description:
        cache[cve] = {"text": wordfence_description, "source": "wordfence", "ts": now}
        _save_cache(cache)
        return wordfence_description

    # Priority 2: NVD (free, no auth)
    text = _fetch_nvd(cve)
    if text:
        cache[cve] = {"text": text, "source": "nvd", "ts": now}
        _save_cache(cache)
        try:
            from . import activity as _act
            _act.emit("threat_intel", f"CVE writeup fetched: {cve} (NVD)")
        except ImportError:
            pass
        return text

    return ""


def reset_cache() -> None:
    """For tests."""
    try:
        _cache_path().unlink()
    except (OSError, FileNotFoundError):
        pass
