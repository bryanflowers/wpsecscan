"""Round-60 #14 — SOCKS5 proxy support (Tor or generic).

Sets WPSECSCAN_PROXY_URL → httpx uses it. Helper checks tor exit IP.

Usage:
    export WPSECSCAN_PROXY_URL=socks5://127.0.0.1:9050
    wpsecscan --target https://example.com
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.error import HTTPError, URLError


def proxy_in_use() -> str:
    return os.environ.get("WPSECSCAN_PROXY_URL", "")


def check_tor_exit() -> dict:
    """Confirm the current connection is via a Tor exit node.
    Returns {ok: bool, ip: str, is_tor: bool, error: str}."""
    if not proxy_in_use():
        return {"ok": False, "error": "WPSECSCAN_PROXY_URL not set"}
    try:
        req = urllib.request.Request(
            "https://check.torproject.org/api/ip",
            headers={"User-Agent": "WPSecScan/tor_proxy"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        return {"ok": True, "ip": d.get("IP", "?"), "is_tor": bool(d.get("IsTor"))}
    except (HTTPError, URLError, OSError, ValueError) as e:
        return {"ok": False, "error": str(e)}
