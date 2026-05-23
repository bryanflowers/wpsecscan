"""CISA Known Exploited Vulnerabilities (KEV) catalog integration.

Downloads + caches CISA's authoritative list of CVEs that are KNOWN to be
exploited in the wild. Any finding whose CVE appears in this list gets a
🔴 "actively exploited" badge — bumps it to the top of the user's fix-list.

CISA updates the feed daily. We cache for 24h.
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 24 * 3600


def _cache_path() -> Path:
    from .. import history as _h
    p = Path(_h._home()) / "cisa_kev.json"
    return p


def _fetch_remote(timeout: float = 20.0) -> dict | None:
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "WPSecScan/cisa-kev"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def load_kev_set(force_refresh: bool = False) -> set[str]:
    """Return the set of CVE IDs currently in the KEV catalog.

    Cached to disk for 24h. On failure, returns whatever is cached, or empty set.
    """
    p = _cache_path()
    if p.exists() and not force_refresh:
        age = time.time() - p.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                # `data.get("cves") or []` defends against a cache file that was hand-edited
                # to {"cves": null} — set(None) raises TypeError which the outer
                # (OSError, ValueError) catch doesn't trap.
                return set(data.get("cves") or [])
            except (OSError, ValueError, TypeError):
                pass
    # Try to refresh
    remote = _fetch_remote()
    if remote and isinstance(remote.get("vulnerabilities"), list):
        cves = {v.get("cveID") for v in remote["vulnerabilities"] if v.get("cveID")}
        try:
            p.write_text(json.dumps({"cves": sorted(cves), "fetched_at": time.time()}), encoding="utf-8")
        except OSError:
            pass
        try:
            from .. import activity as _act
            _act.emit("threat_intel", f"CISA KEV catalog refreshed ({len(cves)} CVEs)")
        except ImportError:
            pass
        return cves
    # Fall back to whatever's cached
    if p.exists():
        try:
            return set(json.loads(p.read_text(encoding="utf-8")).get("cves", []))
        except (OSError, ValueError):
            pass
    return set()


def is_kev(cve: str) -> bool:
    """Quick lookup — is this CVE in the KEV catalog?"""
    return cve in load_kev_set()
