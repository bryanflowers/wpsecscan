"""#52-57 Continuous / multi-target operations.

#52 Continuous mode — `wpsecscan --continuous <url> --interval 6h` loops
#53 Maintenance-mode awareness — pause + retry if /wp-admin/maintenance.php up
#54 Auto-discover WP in a CIDR — `wpsecscan --discover-cidr 192.168.1.0/24`
#55 Auto-discover via cloud accounts — `--discover-cloudflare` etc.
#56 Per-site profile — ~/.wpsecscan/profiles_per_site.json
#57 Scan windowing — `--only-window 02:00-06:00`
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from datetime import datetime, time as dt_time
from pathlib import Path


# ---- #52 continuous mode ----

async def continuous_loop(scan_fn, target: str, interval_s: int,
                           *, max_iterations: int | None = None) -> None:
    """Run `scan_fn(target)` every `interval_s` seconds until SIGINT.
    Diff alerts are the caller's responsibility."""
    i = 0
    while max_iterations is None or i < max_iterations:
        try:
            await scan_fn(target)
        except Exception:  # noqa: BLE001
            # never stop the loop on a single scan failure
            pass
        i += 1
        await asyncio.sleep(interval_s)


# ---- #53 maintenance mode detection ----

async def is_in_maintenance(client) -> bool:
    """Return True if the target is currently in WP maintenance mode."""
    for path in ("/wp-admin/maintenance.php", "/.maintenance"):
        r = await client.get(path)
        if r is not None and r.status_code == 200 and "maintenance" in (r.text or "").lower():
            return True
    return False


# ---- #54 CIDR discovery ----

MAX_DISCOVER_HOSTS = 256  # cap at /24 — bigger ranges would take hours + spam targets


def discover_wp_in_cidr(cidr: str, *, timeout: float = 1.0) -> list[str]:
    """For each host in the CIDR (capped at MAX_DISCOVER_HOSTS = /24), try
    HTTP(S) ports 80/443. Returns candidates for the scanner to fingerprint."""
    out: list[str] = []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses > MAX_DISCOVER_HOSTS:
        # Refuse — caller passed /16, /8, /0 etc.; would scan billions of hosts.
        return []
    for host in net.hosts():
        ip = str(host)
        for port in (443, 80):
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    pass
                # Port open — record candidate; actual WP fingerprinting done by scanner
                scheme = "https" if port == 443 else "http"
                out.append(f"{scheme}://{ip}")
                break
            except (socket.timeout, OSError):
                continue
    return out


# ---- #55 cloud discovery ----

def discover_cloudflare(token: str) -> list[str]:
    """List domains attached to a Cloudflare account. Returns hostnames."""
    if not token:
        return []
    import urllib.request, json as _j
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/zones?per_page=100",
        headers={"Authorization": f"Bearer {token}",
                 "User-Agent": "WPSecScan/discover"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            d = _j.loads(r.read().decode("utf-8"))
        return [z.get("name") for z in d.get("result", []) if z.get("name")]
    except Exception:  # noqa: BLE001
        return []


# ---- #56 per-site profile ----

def _profiles_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "profiles_per_site.json"


def load_profiles() -> dict[str, dict]:
    p = _profiles_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def profile_for(url: str) -> dict:
    """Return the profile dict for `url` or {} if none."""
    return load_profiles().get(url, {})


def save_profile(url: str, profile: dict) -> None:
    d = load_profiles()
    d[url] = profile
    try:
        _profiles_path().write_text(json.dumps(d, indent=2), encoding="utf-8")
    except OSError:
        pass


# ---- #57 scan windowing ----

def _parse_window(spec: str) -> tuple[dt_time, dt_time] | None:
    """Parse `02:00-06:00` into (start, end)."""
    try:
        a, b = spec.split("-", 1)
        ah, am = a.split(":")
        bh, bm = b.split(":")
        return (dt_time(int(ah), int(am)), dt_time(int(bh), int(bm)))
    except (ValueError, AttributeError):
        return None


def is_in_window(spec: str | None, *, now: datetime | None = None) -> bool:
    """Return True if `now` is within the `HH:MM-HH:MM` window. None = always."""
    if not spec:
        return True
    w = _parse_window(spec)
    if not w:
        return True
    now = now or datetime.now()
    n = now.time()
    start, end = w
    if start <= end:
        return start <= n <= end
    # window wraps midnight (e.g. 22:00-04:00)
    return n >= start or n <= end
