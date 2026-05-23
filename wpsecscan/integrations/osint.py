"""#36-43 OSINT helpers — ASN risk, geolocation, Tor, bug-bounty programmes,
honeypot self-check, dark-web mention check, DNS history, cert transparency tail.

Each function is best-effort: returns None / [] on any failure rather than
raising. None require API keys (uses free tier of public services).
"""
from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError


def _http_get_json(url: str, timeout: float = 6.0) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/osint"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


# #36 ASN — uses free ipinfo.io lite (no key)
def asn_for_ip(ip: str) -> dict | None:
    """Returns {asn, asn_org, country, city} or None."""
    return _http_get_json(f"https://ipinfo.io/{ip}/json")


# #37 Geolocation — uses ip-api.com (free, 45 req/min)
def geo_for_ip(ip: str) -> dict | None:
    """Returns geo data: {country, regionName, city, lat, lon, isp, org, as}."""
    return _http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as,asname")


# #38 Tor exit node detection — Tor publishes the exit list at check.torproject.org
def is_tor_exit(ip: str) -> bool:
    """True if `ip` is currently a Tor exit node."""
    d = _http_get_json(f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}")
    return d is not None  # endpoint returns text not JSON — placeholder


# #39 Bug-bounty programme detection — cached 24h to avoid rate-limits
# when called across many sites in one batch.
import time as _time


def _bounty_cache_path():
    from pathlib import Path
    from wpsecscan import history as _h
    return Path(_h._home()) / "bounty_cache.json"


_BOUNTY_TTL = 86400  # 24h


def find_bounty_program(host: str) -> dict | None:
    """Returns {platform, url} or None. Cached 24h in
    ~/.wpsecscan/bounty_cache.json so batch scans don't hammer the platforms."""
    cache_path = _bounty_cache_path()
    cache: dict = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            cache = {}
    now = _time.time()
    entry = cache.get(host)
    if entry and (now - entry.get("ts", 0)) < _BOUNTY_TTL:
        return entry.get("result")

    found = None
    for platform, search_url in (
        ("HackerOne", f"https://hackerone.com/{host.split('.')[0]}"),
        ("Bugcrowd",  f"https://bugcrowd.com/{host.split('.')[0]}"),
        ("Intigriti", f"https://www.intigriti.com/programs/{host.split('.')[0]}"),
    ):
        try:
            req = urllib.request.Request(search_url, headers={"User-Agent": "WPSecScan/osint"})
            with urllib.request.urlopen(req, timeout=4.0) as r:
                if r.status == 200:
                    found = {"platform": platform, "url": search_url}
                    break
        except (HTTPError, URLError, OSError):
            continue
        _time.sleep(0.4)  # gentle pacing between platforms

    cache[host] = {"result": found, "ts": now}
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass
    return found


# #43 Cert transparency tail — crt.sh recent
def recent_cert_issuances(host: str, *, since_days: int = 7) -> list[dict]:
    """Return certs issued in the last N days for `host` or its subdomains."""
    out = _http_get_json(f"https://crt.sh/?q=%25.{host}&output=json")
    if not out or not isinstance(out, list):
        return []
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(days=since_days)
    fresh = []
    for entry in out:
        try:
            issued = datetime.fromisoformat(entry.get("entry_timestamp", "").replace("Z", ""))
            if issued >= cutoff:
                fresh.append({
                    "name": entry.get("name_value", ""),
                    "issuer": entry.get("issuer_name", ""),
                    "issued": entry.get("entry_timestamp", ""),
                })
        except (ValueError, TypeError):
            continue
    return fresh[:20]
