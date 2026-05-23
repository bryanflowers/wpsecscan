"""Per-scan request cache.

Keyed by (method, url, frozenset(sorted params), frozenset(sorted headers)).
TTL = the duration of one scan; cleared on Client.aclose().

Built for the typical scan profile where ~12 checks all GET `/` and ~6 all GET
`/wp-login.php`. With this cache, each unique URL is fetched once.

Thread-safe enough for our use: the GUI scan runs in one worker thread, and
the cache is accessed only inside async code on that thread's event loop.
"""
from __future__ import annotations

import threading
from typing import Any


def _hashable_params(params: Any) -> tuple:
    if not params:
        return ()
    if isinstance(params, dict):
        items = []
        for k, v in sorted(params.items()):
            if isinstance(v, (list, tuple)):
                items.append((k, tuple(v)))
            else:
                items.append((k, v))
        return tuple(items)
    if isinstance(params, (list, tuple)):
        return tuple(sorted(tuple(item) for item in params))
    return (str(params),)


def _hashable_headers(headers: Any) -> tuple:
    if not headers:
        return ()
    if isinstance(headers, dict):
        return tuple(sorted((k.lower(), v) for k, v in headers.items()))
    return ()


class RequestCache:
    """Thread-safe in-memory cache for httpx Response objects.

    NOTE: the cached Response is the same object reference each hit. Callers
    must not mutate the response. wpsecscan checks all read-only fields
    (status_code, headers, text, content) so this is safe in practice."""

    def __init__(self):
        self._lock = threading.Lock()
        self._store: dict[tuple, Any] = {}
        self._hits = 0
        self._misses = 0

    def _key(self, method: str, url: str, params=None, headers=None) -> tuple:
        return (method.upper(), url, _hashable_params(params), _hashable_headers(headers))

    def get(self, method: str, url: str, params=None, headers=None):
        k = self._key(method, url, params, headers)
        with self._lock:
            if k in self._store:
                self._hits += 1
                return self._store[k]
            self._misses += 1
            return None

    def set(self, method: str, url: str, response, params=None, headers=None) -> None:
        k = self._key(method, url, params, headers)
        with self._lock:
            self._store[k] = response

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            ratio = (self._hits / total) if total else 0.0
            return {"hits": self._hits, "misses": self._misses, "ratio": ratio, "size": len(self._store)}
