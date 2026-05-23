"""F2 HAR replay — given a HAR file produced by `--har` (or any HAR 1.2
exporter like Chrome DevTools), re-run the recorded requests against the
current target.

Useful for two scenarios:
1. **Reproduce a flaky finding**: load the HAR from when WPSecScan first
   flagged the issue, replay against the SAME target, and confirm the
   server still returns the same bad response (or that a fix took effect).
2. **Replay authenticated traffic**: capture a HAR with logged-in cookies
   from your browser, feed it to `--replay-har`, and WPSecScan will
   reproduce those exact requests so you can compare before/after a
   change.

The replay does NOT inject new payloads — it's a fidelity re-execution.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx


def load_har(path: Path) -> list[dict]:
    """Parse a HAR 1.2 file. Returns the entries list."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    log = raw.get("log") or {}
    entries = log.get("entries") or []
    return entries if isinstance(entries, list) else []


def _request_kwargs(entry: dict) -> tuple[str, str, dict, bytes | None]:
    """Convert a HAR entry to (method, url, headers_dict, body_bytes)."""
    req = entry.get("request") or {}
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    headers: dict[str, str] = {}
    for h in req.get("headers") or []:
        name = h.get("name", "")
        if not name or name.lower().startswith(":"):  # skip HTTP/2 pseudo-headers
            continue
        # Skip hop-by-hop and headers httpx manages itself
        if name.lower() in ("host", "content-length", "connection", "transfer-encoding",
                            "accept-encoding"):
            continue
        headers[name] = h.get("value", "")
    body: bytes | None = None
    pd = req.get("postData") or {}
    if pd.get("text"):
        body = pd["text"].encode("utf-8", errors="replace")
    return method, url, headers, body


async def _replay_one(client: httpx.AsyncClient, entry: dict, *,
                       target_origin: str | None = None) -> dict:
    method, url, headers, body = _request_kwargs(entry)
    if target_origin:
        # Rewrite the origin to point at a different target while keeping
        # path + query intact. Lets you "replay this traffic but against
        # staging instead of prod" etc.
        try:
            orig = urlparse(url)
            new = urlparse(target_origin)
            url = f"{new.scheme}://{new.netloc}{orig.path or '/'}"
            if orig.query:
                url += "?" + orig.query
        except (ValueError, AttributeError):
            pass
    out: dict[str, Any] = {
        "request": {"method": method, "url": url},
        "ok": False,
    }
    try:
        resp = await client.request(method, url, headers=headers, content=body)
        out["ok"] = True
        out["status"] = resp.status_code
        out["body_len"] = len(resp.content or b"")
        out["headers"] = dict(resp.headers)
    except (httpx.HTTPError, ValueError, RuntimeError) as e:
        out["error"] = str(e)[:200]
    return out


async def replay(har_path: Path, *, target_origin: str | None = None,
                  concurrency: int = 5, timeout: float = 15.0) -> list[dict]:
    """Replay every request in the HAR file. Returns a list of result dicts.

    target_origin: if set (e.g. https://staging.example.com), rewrites every
    recorded URL to use that scheme+host while preserving path+query.
    """
    entries = load_har(har_path)
    if not entries:
        return []
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(c: httpx.AsyncClient, e: dict) -> dict:
        async with sem:
            return await _replay_one(c, e, target_origin=target_origin)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return await asyncio.gather(*(_bounded(client, e) for e in entries))


def diff(before: list[dict], after: list[dict]) -> dict[str, Any]:
    """Compare two replay result lists. Returns {changed, same, errors}."""
    if len(before) != len(after):
        return {"summary": f"Length mismatch: before={len(before)} after={len(after)}"}
    changed: list[dict] = []
    same = 0
    errors = 0
    for b, a in zip(before, after):
        if not a.get("ok") or not b.get("ok"):
            errors += 1
            continue
        if b.get("status") != a.get("status"):
            changed.append({"url": a["request"]["url"], "method": a["request"]["method"],
                            "status_before": b.get("status"), "status_after": a.get("status"),
                            "len_before": b.get("body_len"), "len_after": a.get("body_len")})
        elif abs((b.get("body_len") or 0) - (a.get("body_len") or 0)) > 256:
            changed.append({"url": a["request"]["url"], "method": a["request"]["method"],
                            "status": a.get("status"),
                            "len_before": b.get("body_len"), "len_after": a.get("body_len")})
        else:
            same += 1
    return {"same": same, "errors": errors, "changed": changed}


def run_replay_sync(har_path: Path, target_origin: str | None = None) -> list[dict]:
    """Convenience sync entry point — wraps asyncio.run."""
    return asyncio.run(replay(har_path, target_origin=target_origin))
