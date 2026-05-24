"""Fan-out scanner across sites — Round-64 #164.

Used by `wpsecscan sites scan --all` to run N sites concurrently
instead of serially.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable


async def scan_sites_parallel(
    sites: list[dict],
    scan_one: Callable[[dict], Awaitable[Any]],
    *,
    max_concurrency: int = 4,
    progress: Callable[[str, str], None] | None = None,
) -> list[dict]:
    """Run `scan_one(site)` concurrently across `sites`.

    Returns a list of {"site": site, "result": result, "error": str|None}.
    """
    sem = asyncio.Semaphore(max_concurrency)
    results: list[dict] = []

    async def _wrap(site: dict) -> None:
        async with sem:
            sid = site.get("name") or site.get("url") or "?"
            if progress:
                progress(sid, "started")
            try:
                r = await scan_one(site)
                results.append({"site": site, "result": r, "error": None})
                if progress:
                    progress(sid, "complete")
            except Exception as e:  # noqa: BLE001
                results.append({"site": site, "result": None, "error": str(e)})
                if progress:
                    progress(sid, f"error: {e}")

    await asyncio.gather(*(_wrap(s) for s in sites))
    return results
