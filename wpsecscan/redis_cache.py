"""K28 Redis-backed CVE DB share.

For teams scanning many sites in parallel from a single host, the per-process
file-based CVE DB cache is duplicated 10-20x. Pointing them at a shared Redis
lets all processes hit the same in-memory copy.

Activates only when:
  1. The `redis` python package is installed
  2. The user passes `--redis-url redis://host:6379/0` (or sets WPSECSCAN_REDIS_URL)

No-op fallback otherwise — the file cache continues to work as before.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache


CACHE_KEY_PREFIX = "wpsecscan:"
DEFAULT_TTL_SECONDS = 6 * 3600  # 6h — long enough to amortise the fetch, short enough to refresh


def _has_redis() -> bool:
    try:
        import redis  # noqa: F401
        return True
    except ImportError:
        return False


@lru_cache(maxsize=1)
def _client():
    """Return a redis.Redis client, or None."""
    if not _has_redis():
        return None
    url = os.environ.get("WPSECSCAN_REDIS_URL")
    if not url:
        return None
    try:
        import redis
        c = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2.0)
        # Cheap ping to verify
        c.ping()
        return c
    except Exception:  # noqa: BLE001
        return None


def get(key: str):
    """Get a JSON-decoded value from the shared cache, or None on miss."""
    c = _client()
    if c is None:
        return None
    try:
        raw = c.get(CACHE_KEY_PREFIX + key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return None


def set(key: str, value, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> bool:
    """Store a JSON-encoded value in the shared cache. Returns False on failure."""
    c = _client()
    if c is None:
        return False
    try:
        c.setex(CACHE_KEY_PREFIX + key, ttl_seconds, json.dumps(value))
        return True
    except Exception:  # noqa: BLE001
        return False


def is_enabled() -> bool:
    """True if the Redis cache is available and reachable."""
    return _client() is not None
