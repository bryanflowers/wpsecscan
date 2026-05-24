"""Shared httpx.AsyncClient pool across checks — Round-64 #165.

Instead of each check opening its own httpx client, share one per
(base_url, scan). Reduces TCP/TLS handshakes by an order of magnitude
on a typical 100-check scan.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import httpx


class SharedClientPool:
    """One AsyncClient per base_url, shared by all checks for that scan.

    Usage:
        async with SharedClientPool() as pool:
            client = await pool.get("https://example.com")
            # ... pass `client` into checks ...
    """

    def __init__(self, *, default_timeout: float = 15.0, max_connections: int = 20) -> None:
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._lock = asyncio.Lock()
        self._timeout = default_timeout
        self._max_connections = max_connections

    async def get(self, base_url: str, **kwargs: Any) -> httpx.AsyncClient:
        async with self._lock:
            if base_url not in self._clients:
                limits = httpx.Limits(
                    max_connections=self._max_connections,
                    max_keepalive_connections=self._max_connections,
                    keepalive_expiry=30.0,
                )
                self._clients[base_url] = httpx.AsyncClient(
                    base_url=base_url,
                    timeout=self._timeout,
                    limits=limits,
                    http2=True,
                    **kwargs,
                )
            return self._clients[base_url]

    async def close(self) -> None:
        async with self._lock:
            for c in self._clients.values():
                with contextlib.suppress(Exception):
                    await c.aclose()
            self._clients.clear()

    async def __aenter__(self) -> "SharedClientPool":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()
