from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from urllib.parse import urljoin

import httpx

from .cache import RequestCache

DEFAULT_UA = "WPSecScan/1.0 (+defensive-recon)"

# B2 (adaptive throttle) constants
_THROTTLE_TRIGGER_STATUSES = (429, 503)
_THROTTLE_BACKOFF_STEPS = (0.5, 1.5, 3.0, 6.0)  # seconds, capped
_RECOVER_AFTER_OK_STREAK = 20  # restore full concurrency after 20 consecutive 2xx/3xx


class Client:
    """Thin wrapper around httpx.AsyncClient with a per-host semaphore.

    cache=True attaches a per-Client RequestCache so repeated GETs of the same
    URL (very common across passive checks — `/` is hit by ~12 checks) are
    served from memory after the first fetch.

    adaptive_throttle=True (default since the round-Q update) auto-reduces the
    concurrency window when the target returns 429/503, and restores it after
    a streak of clean responses.

    har=True records every request/response to an in-memory HAR-shaped list
    accessible via `har_log()`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 15.0,
        user_agent: str = DEFAULT_UA,
        concurrency: int = 10,
        verify: bool = True,
        cache: bool = False,
        adaptive_throttle: bool = True,
        har: bool = False,
        rotate_ua: bool = False,  # #3 — randomise UA per request from ua_rotation pool
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._initial_concurrency = concurrency
        self._current_concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)
        self._rotate_ua = rotate_ua
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            follow_redirects=False,
            verify=verify,
            http2=True,
        )
        self._cache: RequestCache | None = RequestCache() if cache else None
        # B2 adaptive throttle state
        self._adaptive = adaptive_throttle
        self._ok_streak = 0
        self._throttle_hits = 0
        self._extra_delay_s = 0.0
        self._throttle_lock = asyncio.Lock()
        # E2 HAR recorder
        self._har_enabled = har
        self._har_entries: list[dict] = []

    async def aclose(self) -> None:
        if self._cache:
            self._cache.clear()
        await self._client.aclose()

    def cache_stats(self) -> dict | None:
        return self._cache.stats() if self._cache else None

    def throttle_stats(self) -> dict:
        """Return current adaptive-throttle state. Useful for the GUI status bar."""
        return {
            "concurrency_initial": self._initial_concurrency,
            "concurrency_current": self._current_concurrency,
            "throttle_hits": self._throttle_hits,
            "ok_streak": self._ok_streak,
            "extra_delay_s": round(self._extra_delay_s, 2),
        }

    def har_log(self) -> list[dict]:
        """Return the accumulated HAR entries. Use har_export() for a complete HAR doc."""
        return list(self._har_entries)

    def har_export(self) -> dict:
        """Return a complete HAR 1.2 document wrapping the recorded entries."""
        from datetime import datetime, timezone
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "WPSecScan", "version": "1.0"},
                "browser": {"name": "httpx", "version": httpx.__version__},
                "pages": [],
                "entries": self._har_entries,
                "_startedDateTime": datetime.now(timezone.utc).isoformat(),
            }
        }

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/"))

    async def _adapt_on_throttle(self) -> None:
        """B2: shrink concurrency + add jitter when the target throttles us."""
        async with self._throttle_lock:
            self._throttle_hits += 1
            self._ok_streak = 0
            # Halve concurrency, min 1
            if self._current_concurrency > 1:
                self._current_concurrency = max(1, self._current_concurrency // 2)
                # Recreate semaphore at the new size
                self._sem = asyncio.Semaphore(self._current_concurrency)
            # Add exponential backoff for the *next* request
            idx = min(self._throttle_hits - 1, len(_THROTTLE_BACKOFF_STEPS) - 1)
            self._extra_delay_s = _THROTTLE_BACKOFF_STEPS[idx]

    async def _adapt_on_ok(self) -> None:
        """B2: count consecutive clean responses; restore concurrency after enough."""
        async with self._throttle_lock:
            self._ok_streak += 1
            if (
                self._ok_streak >= _RECOVER_AFTER_OK_STREAK
                and self._current_concurrency < self._initial_concurrency
            ):
                # Step concurrency back up by one
                self._current_concurrency = min(self._initial_concurrency, self._current_concurrency + 1)
                self._sem = asyncio.Semaphore(self._current_concurrency)
                self._ok_streak = 0
                # Decay extra delay
                self._extra_delay_s = max(0.0, self._extra_delay_s / 2)

    def _record_har(self, method: str, url: str, kwargs: dict, response, elapsed_ms: float) -> None:
        """Append one HAR entry. Strips credential headers (Authorization, Cookie,
        X-API-Key, X-Auth-Token, X-Access-Token, Set-Cookie) so a HAR shared in a
        bug report can't leak admin creds."""
        if not self._har_enabled:
            return
        from datetime import datetime, timezone
        _SENSITIVE_REQ = frozenset((
            "authorization", "cookie",
            "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
            "proxy-authorization",
        ))
        _SENSITIVE_RESP = frozenset(("set-cookie", "authorization", "x-auth-token"))
        req_headers = []
        for k, v in (kwargs.get("headers") or {}).items():
            value = "<redacted>" if k.lower() in _SENSITIVE_REQ else str(v)
            req_headers.append({"name": str(k), "value": value})
        resp_status = response.status_code if response is not None else 0
        resp_headers = []
        body_text = ""
        if response is not None:
            for k, v in (response.headers or {}).items():
                value = "<redacted>" if k.lower() in _SENSITIVE_RESP else str(v)
                resp_headers.append({"name": str(k), "value": value})
            # Cap body BEFORE decoding to avoid materialising a multi-MB response
            # as a Python str only to throw it away.
            raw = (response.content or b"")[:8000]
            body_text = raw.decode("utf-8", errors="replace")
        self._har_entries.append({
            "startedDateTime": datetime.now(timezone.utc).isoformat(),
            "time": elapsed_ms,
            "request": {
                "method": method.upper(),
                "url": url,
                "httpVersion": "HTTP/1.1",
                "headers": req_headers,
                "queryString": [{"name": str(k), "value": str(v)} for k, v in (kwargs.get("params") or {}).items()],
                "postData": (
                    {"mimeType": "application/x-www-form-urlencoded", "text": str(kwargs.get("data") or kwargs.get("json") or kwargs.get("content") or "")[:4000]}
                    if (kwargs.get("data") or kwargs.get("json") or kwargs.get("content")) else None
                ),
                "headersSize": -1, "bodySize": -1,
            },
            "response": {
                "status": resp_status,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": resp_headers,
                "content": {"size": len(body_text), "mimeType": "", "text": body_text},
                "redirectURL": (response.headers.get("location", "") if response is not None else ""),
                "headersSize": -1, "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": elapsed_ms, "receive": 0},
        })

    async def request(
        self,
        method: str,
        path: str,
        *,
        follow_redirects: bool = False,
        **kwargs,
    ) -> httpx.Response | None:
        url = self.url(path)
        # Cache only safe, idempotent GET/HEAD with no body. POST/PUT/DELETE never cached.
        cacheable = (
            self._cache is not None
            and method.upper() in ("GET", "HEAD")
            and kwargs.get("content") is None
            and kwargs.get("data") is None
            and kwargs.get("json") is None
        )
        params = kwargs.get("params")
        headers = kwargs.get("headers")
        if cacheable:
            hit = self._cache.get(method, url, params=params, headers=headers)
            if hit is not None:
                return hit
        # B2: optionally sleep for the adaptive backoff window before acquiring sem.
        # Snapshot the value under the lock so a concurrent _adapt_on_throttle() can't
        # leave us reading a half-written float.
        if self._adaptive:
            async with self._throttle_lock:
                delay = self._extra_delay_s
            if delay > 0:
                await asyncio.sleep(delay)
        # #3 UA rotation — if enabled, override User-Agent per request
        if getattr(self, "_rotate_ua", False):
            try:
                from . import ua_rotation as _ua
                merged_headers = dict(kwargs.get("headers") or {})
                merged_headers.setdefault("User-Agent", _ua.random_ua())
                kwargs["headers"] = merged_headers
            except ImportError:
                pass
        async with self._sem:
            t0 = time.perf_counter()
            try:
                r = await self._client.request(
                    method, url, follow_redirects=follow_redirects, **kwargs
                )
            except (httpx.TimeoutException, httpx.TransportError, httpx.RequestError, httpx.HTTPStatusError):
                # HTTPStatusError can only raise if a caller sets follow_redirects=True
                # AND a check explicitly calls .raise_for_status() on the response.
                self._record_har(method, url, kwargs, None, (time.perf_counter() - t0) * 1000)
                return None
            elapsed_ms = (time.perf_counter() - t0) * 1000
        self._record_har(method, url, kwargs, r, elapsed_ms)
        # B2: feed result into the adaptive throttle decision
        if self._adaptive:
            if r.status_code in _THROTTLE_TRIGGER_STATUSES:
                await self._adapt_on_throttle()
            elif 200 <= r.status_code < 400:
                await self._adapt_on_ok()
        if cacheable and r is not None:
            self._cache.set(method, url, r, params=params, headers=headers)
        return r

    async def get(self, path: str, **kwargs) -> httpx.Response | None:
        return await self.request("GET", path, **kwargs)

    async def head(self, path: str, **kwargs) -> httpx.Response | None:
        return await self.request("HEAD", path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response | None:
        return await self.request("POST", path, **kwargs)


@asynccontextmanager
async def client(base_url: str, **kwargs):
    c = Client(base_url, **kwargs)
    try:
        yield c
    finally:
        await c.aclose()
