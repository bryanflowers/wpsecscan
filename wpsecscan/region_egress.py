"""N39 Per-region egress routing.

GDPR + similar regimes restrict where personal data may transit. If you're
scanning EU customers, every probe payload + every response body should stay
on EU infrastructure. This module lets the user pin scans to a regional
proxy (set via env or CLI).

Implementation: when WPSECSCAN_REGION=eu-west-1 (or eq), the http client
routes through the corresponding HTTP/HTTPS proxy URL set by the same prefix:
  WPSECSCAN_PROXY_EU_WEST_1=http://eu-proxy:3128

No proxy = no enforcement (just a warning). Names matched case-insensitively.
"""
from __future__ import annotations

import os


def _env_key(region: str) -> str:
    """Convert 'eu-west-1' -> 'WPSECSCAN_PROXY_EU_WEST_1'."""
    return "WPSECSCAN_PROXY_" + region.upper().replace("-", "_")


def configured_region() -> str | None:
    """Return the active region name, or None."""
    region = (os.environ.get("WPSECSCAN_REGION") or "").strip()
    return region or None


def proxy_for_region(region: str | None = None) -> str | None:
    """Return the proxy URL for the active region, or None."""
    region = region or configured_region()
    if not region:
        return None
    return os.environ.get(_env_key(region)) or None


def httpx_proxies() -> dict | None:
    """Build the dict shape httpx.AsyncClient expects for `proxies=`.
    Returns None when no region/proxy is configured."""
    proxy = proxy_for_region()
    if not proxy:
        return None
    return {"http://": proxy, "https://": proxy}


def warn_if_unenforced() -> str | None:
    """If WPSECSCAN_REGION is set but no proxy is configured for it,
    return a warning string. Caller is responsible for displaying."""
    region = configured_region()
    if not region:
        return None
    if proxy_for_region(region):
        return None
    return (
        f"WPSECSCAN_REGION is set to {region!r} but no proxy is configured "
        f"(expected env {_env_key(region)}); scans will egress from the "
        "current host's default network — region restriction NOT enforced."
    )
