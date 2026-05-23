"""VirusTotal URL / IP lookup.

Opt-in via --vt-token (free tier: 4 req/min, 500/day). Submits the target's
IP and any external JS hosts seen in `js_supply_chain` for reputation check.
Flags if VT reports any vendor consensus on "malicious".
"""
from __future__ import annotations

import base64
import json
import urllib.request
from urllib.error import HTTPError, URLError


def _vt_request(path: str, token: str, timeout: float = 8.0) -> dict | None:
    url = f"https://www.virustotal.com/api/v3/{path}"
    req = urllib.request.Request(url, headers={
        "x-apikey": token,
        "User-Agent": "WPSecScan/virustotal",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def lookup_url(url: str, token: str) -> dict | None:
    """Look up a URL. VT requires URL-safe-base64 of the URL minus padding."""
    if not token:
        return None
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).rstrip(b"=").decode("ascii")
    data = _vt_request(f"urls/{encoded}", token)
    if not data:
        return None
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    out = {
        "url": url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "permalink": f"https://www.virustotal.com/gui/url/{encoded}",
    }
    try:
        from .. import activity as _act
        total = sum((stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")))
        _act.emit("threat_intel",
                  f"VirusTotal URL: {out['malicious']} malicious / {total} engines")
    except ImportError:
        pass
    return out


def lookup_ip(ip: str, token: str) -> dict | None:
    """Look up an IPv4 address."""
    if not token:
        return None
    data = _vt_request(f"ip_addresses/{ip}", token)
    if not data:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    out = {
        "ip": ip,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "country": attrs.get("country", "?"),
        "as_owner": attrs.get("as_owner", "?"),
        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }
    try:
        from .. import activity as _act
        _act.emit("threat_intel",
                  f"VirusTotal IP {ip}: {out['malicious']} malicious / {out['country']}")
    except ImportError:
        pass
    return out
