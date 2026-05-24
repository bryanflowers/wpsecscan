"""Test-framework utilities for check authors — Round-64 #150.

Centralises FakeClient / FakeResponse / _ctx() helpers so check tests
don't reinvent them. Existing tests can be migrated as needed.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any


def run(coro):
    """Drop-in for the per-test `_run(coro)` helper."""
    return asyncio.get_event_loop().run_until_complete(coro) if asyncio.get_event_loop().is_running() is False else asyncio.run(coro)


def _ctx(**overrides) -> dict:
    """Default ctx for check() calls. Override with kwargs."""
    base = {"step": lambda _s: None, "shared": {}}
    base.update(overrides)
    return base


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", *, json_body: Any = None, headers: dict | None = None, url: str = "", content: bytes | None = None) -> None:
        self.status_code = status_code
        self.text = text if text else (json.dumps(json_body) if json_body is not None else "")
        self.content = content if content is not None else (self.text or "").encode("utf-8")
        self.headers = headers or {}
        self.url = url
        self._json_body = json_body

    def json(self):
        if self._json_body is not None:
            return self._json_body
        return json.loads(self.text)


class FakeClient:
    """A scriptable async HTTP client for check tests.

    Usage:
        c = FakeClient({
            ("GET", "/foo"): FakeResponse(200, '{"ok": true}'),
        })
        result = run(some_check.check(c, _ctx()))
    """

    def __init__(self, responses: dict[tuple[str, str], FakeResponse] | None = None, *, default: FakeResponse | None = None, base_url: str = "https://test.example.com") -> None:
        self.responses = responses or {}
        self.default = default
        self.base_url = base_url
        self.calls: list[tuple[str, str]] = []

    def url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return self.base_url.rstrip("/") + "/" + path.lstrip("/")

    async def request(self, method: str, path: str, **_kwargs):
        self.calls.append((method, path))
        return self.responses.get((method, path), self.default)

    async def get(self, path: str, **kw):
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw):
        return await self.request("POST", path, **kw)

    async def head(self, path: str, **kw):
        return await self.request("HEAD", path, **kw)

    async def aclose(self) -> None:
        pass


def assert_finding_severity(findings: list, severity: str, title_contains: str | None = None) -> None:
    """Assert at least one finding matches."""
    hits = [f for f in findings if (f.severity if hasattr(f, "severity") else f.get("severity")) == severity]
    if title_contains:
        hits = [
            f for f in hits
            if title_contains.lower() in (f.title if hasattr(f, "title") else f.get("title", "")).lower()
        ]
    if not hits:
        raise AssertionError(
            f"No finding with severity={severity!r}"
            + (f" + title containing {title_contains!r}" if title_contains else "")
            + f"; got {[(f.severity if hasattr(f, 'severity') else f.get('severity'), f.title if hasattr(f, 'title') else f.get('title')) for f in findings]}"
        )
