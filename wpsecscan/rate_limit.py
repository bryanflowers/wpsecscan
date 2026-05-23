"""#4 (from wpscan) — external-API rate-limit awareness.

Used by integration modules that call third-party APIs (wpscan API,
VirusTotal, GitHub code-search, HIBP, AbuseIPDB). Reads `Retry-After`
and standard `X-RateLimit-*` headers, sleeps automatically, and exposes
remaining-quota for end-of-scan reporting.

This is separate from the per-host adaptive throttle in `http.py` — that
one handles scan-target rate-limiting (429/503 from the WP site). This
module handles OUR rate-limit against third-party services.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict


# Per-service state. Capped to MAX_SERVICES with LRU eviction so a runaway
# integration emitting unique service names can't grow the dict indefinitely
# across long-running scans (e.g. daemon mode running for weeks).
MAX_SERVICES = 64
_state: dict[str, dict] = defaultdict(dict)
_touch_order: list[str] = []


def _touch(service: str) -> None:
    if service in _touch_order:
        _touch_order.remove(service)
    _touch_order.append(service)
    while len(_state) > MAX_SERVICES:
        old = _touch_order.pop(0)
        _state.pop(old, None)


def clear() -> None:
    """Drop all per-service quota state. Call between batch scans if you
    don't want one target's quota state bleeding into the next's."""
    _state.clear()
    _touch_order.clear()


def update_from_headers(service: str, headers) -> None:
    """Parse rate-limit headers from any API response. Tolerant to missing
    headers — supports the three common conventions:
      - GitHub / Patchstack: X-RateLimit-Limit / X-RateLimit-Remaining / X-RateLimit-Reset
      - HIBP: 'Retry-After' (seconds)
      - VirusTotal: X-VT-API-Quota-Remaining (custom)
    """
    if not headers:
        return
    h = {k.lower(): v for k, v in (headers.items() if hasattr(headers, "items") else [])}
    s = _state[service]
    _touch(service)
    try:
        if "x-ratelimit-remaining" in h:
            s["remaining"] = int(h["x-ratelimit-remaining"])
        if "x-ratelimit-limit" in h:
            s["limit"] = int(h["x-ratelimit-limit"])
        if "x-ratelimit-reset" in h:
            s["reset_at"] = int(h["x-ratelimit-reset"])
        if "x-vt-api-quota-remaining" in h:
            s["remaining"] = int(h["x-vt-api-quota-remaining"])
        if "retry-after" in h:
            try:
                s["retry_after_s"] = int(h["retry-after"])
            except ValueError:
                s["retry_after_s"] = 60
    except (ValueError, TypeError):
        pass


def should_back_off(service: str) -> float:
    """Return the seconds to sleep before the next call to `service`, or 0.
    Conservative: triggers when remaining <= 1 OR retry-after header set."""
    s = _state.get(service) or {}
    rem = s.get("remaining")
    if isinstance(rem, int) and rem <= 1 and s.get("reset_at"):
        wait = max(0, s["reset_at"] - int(time.time()))
        return min(wait, 60)  # cap at 60s so a misconfigured server can't stall us
    if s.get("retry_after_s"):
        wait = int(s.pop("retry_after_s"))
        return min(wait, 60)
    return 0


async def back_off_if_needed(service: str) -> None:
    """Async sleep helper. Call before issuing the next request to `service`."""
    delay = should_back_off(service)
    if delay > 0:
        await asyncio.sleep(delay)


def snapshot() -> dict[str, dict]:
    """For end-of-scan stats panel — copy of all known service quotas."""
    return {k: dict(v) for k, v in _state.items()}
