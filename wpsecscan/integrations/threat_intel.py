"""Round-60 #22 — threat intel enrichment per finding (VirusTotal + GreyNoise).

Each function takes an indicator (IP / URL) and returns a small dict.
Disk-cached 24h to avoid burning API quota on batch scans.

Env vars:
  VIRUSTOTAL_API_KEY
  GREYNOISE_API_KEY
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError


_TTL = 86400  # 24h


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _cache_path() -> Path:
    return _home() / "threat_intel_cache.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(d: dict) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(d), encoding="utf-8")
    except OSError:
        pass


def _cached(key: str) -> dict | None:
    cache = _load_cache()
    entry = cache.get(key)
    if not entry:
        return None
    if (time.time() - int(entry.get("ts", 0))) > _TTL:
        return None
    return entry.get("data")


def _store(key: str, data: dict) -> None:
    cache = _load_cache()
    cache[key] = {"ts": int(time.time()), "data": data}
    # keep cache lean
    if len(cache) > 500:
        keys = sorted(cache, key=lambda k: cache[k].get("ts", 0))[:100]
        for k in keys:
            cache.pop(k, None)
    _save_cache(cache)


def _http_get_json(url: str, headers: dict | None = None, timeout: float = 8.0) -> dict | None:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/threat_intel",
                                                  **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status >= 400:
                return None
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def virustotal_url(url: str) -> dict:
    """VirusTotal URL report — returns {malicious, total_engines, ...} or {}."""
    if not url:
        return {}
    key = "vt:" + url
    if (c := _cached(key)) is not None:
        return c
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {}
    # VT URL ID is base64url(url) without padding
    import base64
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).rstrip(b"=").decode("ascii")
    d = _http_get_json(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": api_key},
    ) or {}
    stats = (d.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
    result = {
        "malicious":      int(stats.get("malicious", 0)),
        "suspicious":     int(stats.get("suspicious", 0)),
        "total_engines":  sum(int(v) for v in stats.values() if isinstance(v, (int, float))),
        "last_analysis":  (d.get("data") or {}).get("attributes", {}).get("last_analysis_date"),
    }
    if result["total_engines"]:
        _store(key, result)
    return result


def greynoise_ip(ip: str) -> dict:
    if not ip:
        return {}
    key = "gn:" + ip
    if (c := _cached(key)) is not None:
        return c
    api_key = os.environ.get("GREYNOISE_API_KEY", "")
    headers = {"key": api_key} if api_key else {}
    # GreyNoise community endpoint is free + key-less
    base = "https://api.greynoise.io/v3/community/" if not api_key else f"https://api.greynoise.io/v2/noise/quick/{ip}"
    d = _http_get_json(base + ip if not api_key else base, headers=headers) or {}
    result = {
        "noise":      bool(d.get("noise") or d.get("code") == "0x01"),
        "classification": d.get("classification", "unknown"),
        "name":       d.get("name", ""),
        "last_seen":  d.get("last_seen", ""),
    }
    if d:
        _store(key, result)
    return result


def enrich_finding(finding: dict) -> dict:
    """Return enrichment data to add to a finding's `extra` dict."""
    out: dict = {}
    url = finding.get("url", "")
    if url:
        vt = virustotal_url(url)
        if vt and vt.get("total_engines"):
            out["virustotal"] = vt
    # Pull IPs from evidence
    import re
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", finding.get("evidence", ""))
    if ips:
        out["greynoise"] = {ip: greynoise_ip(ip) for ip in set(ips)}
    return out
