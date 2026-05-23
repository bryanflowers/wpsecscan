"""EPSS (Exploit Prediction Scoring System) integration.

Each CVE gets a percentile from first.org's free EPSS feed. The percentile
indicates how likely the CVE is to be exploited in the next 30 days, relative
to all other CVEs. 95th percentile = "very likely to be exploited".

API: https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678
Limit: ~100 CVEs per call. Free, no auth.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def _cache_path() -> Path:
    from .. import history as _h
    p = Path(_h._home()) / "epss_cache.json"
    return p


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


def lookup_scores(cves: list[str]) -> dict[str, dict]:
    """Return {cve: {epss, percentile, date}} for each CVE.

    Cache hits served from disk; misses fetched in batches of 100.
    """
    cache = _load_cache()
    now = time.time()
    fresh: dict[str, dict] = {}
    to_fetch: list[str] = []
    for cve in cves:
        entry = cache.get(cve)
        if entry and (now - entry.get("ts", 0) < CACHE_TTL_SECONDS):
            fresh[cve] = {"epss": entry["epss"], "percentile": entry["percentile"], "date": entry["date"]}
        else:
            to_fetch.append(cve)

    # Batch fetch (chunks of 100)
    for i in range(0, len(to_fetch), 100):
        batch = to_fetch[i:i + 100]
        url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/epss"})
            with urllib.request.urlopen(req, timeout=10.0) as r:
                if r.status != 200:
                    continue
                data = json.loads(r.read().decode("utf-8"))
                for row in data.get("data", []) or []:
                    cve = row.get("cve")
                    if not cve:
                        continue
                    entry = {
                        "epss": float(row.get("epss", 0)),
                        "percentile": float(row.get("percentile", 0)),
                        "date": row.get("date", ""),
                        "ts": now,
                    }
                    cache[cve] = entry
                    fresh[cve] = {k: v for k, v in entry.items() if k != "ts"}
        except (HTTPError, URLError, OSError, ValueError):
            continue
    _save_cache(cache)
    if cves:
        try:
            from .. import activity as _act
            hits = len(cves) - len(to_fetch)
            _act.emit("threat_intel",
                      f"EPSS scored {len(cves)} CVE(s) · {hits} cache hit(s), {len(to_fetch)} fetched")
        except ImportError:
            pass
    return fresh


def percentile_label(pct: float) -> str:
    """Human-friendly band for the EPSS percentile (0-1)."""
    p = pct * 100
    if p >= 95:
        return "highly likely (95th+ percentile)"
    if p >= 80:
        return "very likely (80-95th percentile)"
    if p >= 50:
        return "above-average likelihood"
    return "low likelihood"
