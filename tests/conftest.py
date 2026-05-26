"""Shared fixtures: a fake Client that returns scripted responses per path."""
from __future__ import annotations

from dataclasses import dataclass

import pytest


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""
    content: bytes = b""
    headers: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if not self.content and self.text:
            self.content = self.text.encode("utf-8", errors="replace")
        if not self.text and self.content:
            try:
                self.text = self.content.decode("utf-8", errors="replace")
            except Exception:
                self.text = ""

    def json(self):
        import json as _json
        return _json.loads(self.text)


class FakeClient:
    """Drop-in replacement for wpsecscan.http.Client in tests."""

    def __init__(self, base_url: str = "https://example.com", responses: dict | None = None):
        self.base_url = base_url
        self.responses = responses or {}
        self.requests: list[tuple[str, str, dict]] = []

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return self.base_url.rstrip("/") + "/" + path.lstrip("/")

    def _lookup(self, method: str, path: str, params=None):
        # Try exact path match first, then path-only fallback, then "*" wildcard.
        key_with_params = (method, path, repr(params or {}))
        if key_with_params in self.responses:
            return self.responses[key_with_params]
        if (method, path) in self.responses:
            return self.responses[(method, path)]
        if path in self.responses:
            return self.responses[path]
        # Strip a query string before falling back to the bare path.
        bare = path.split("?", 1)[0]
        if bare in self.responses:
            return self.responses[bare]
        if "*" in self.responses:
            return self.responses["*"]
        return None

    async def request(self, method: str, path: str, **kwargs):
        self.requests.append((method, path, kwargs))
        params = kwargs.get("params")
        return self._lookup(method, path, params)

    async def get(self, path: str, **kwargs):
        return await self.request("GET", path, **kwargs)

    async def head(self, path: str, **kwargs):
        return await self.request("HEAD", path, **kwargs)

    async def post(self, path: str, **kwargs):
        return await self.request("POST", path, **kwargs)


@pytest.fixture
def fake_client():
    return FakeClient


@pytest.fixture
def ctx():
    return {
        "target": "https://example.com",
        "shared": {},
        "step": lambda _s: None,
    }
