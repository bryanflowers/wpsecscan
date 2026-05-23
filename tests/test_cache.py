"""RequestCache + Client integration: idempotent GETs share a single fetch."""
from __future__ import annotations

import asyncio
import threading

from wpsecscan.cache import RequestCache


def test_first_get_is_miss_second_is_hit():
    c = RequestCache()
    assert c.get("GET", "https://x/") is None
    c.set("GET", "https://x/", "resp-A")
    assert c.get("GET", "https://x/") == "resp-A"
    s = c.stats()
    assert s["hits"] == 1
    assert s["misses"] == 1
    assert s["size"] == 1


def test_different_params_are_different_keys():
    c = RequestCache()
    c.set("GET", "https://x/wp-json", "list", params={"page": 1})
    c.set("GET", "https://x/wp-json", "list2", params={"page": 2})
    assert c.get("GET", "https://x/wp-json", params={"page": 1}) == "list"
    assert c.get("GET", "https://x/wp-json", params={"page": 2}) == "list2"
    assert c.stats()["size"] == 2


def test_header_keys_are_case_insensitive():
    c = RequestCache()
    c.set("GET", "https://x/", "r", headers={"X-Test": "1"})
    # Should hit even though the header key is lowercased on lookup
    assert c.get("GET", "https://x/", headers={"x-test": "1"}) == "r"


def test_method_uppercased():
    c = RequestCache()
    c.set("get", "https://x/", "r")
    assert c.get("GET", "https://x/") == "r"


def test_clear_resets_store_but_keeps_stats():
    c = RequestCache()
    c.set("GET", "https://x/", "r")
    c.get("GET", "https://x/")
    c.clear()
    assert c.stats()["size"] == 0
    # Hits/misses are *not* reset by clear (we want lifetime stats per scan)
    assert c.stats()["hits"] >= 1


def test_thread_safety_under_concurrent_writes():
    c = RequestCache()
    errors: list[Exception] = []

    def worker(n: int):
        try:
            for i in range(100):
                c.set("GET", f"https://x/{n}-{i}", f"resp-{n}-{i}")
                c.get("GET", f"https://x/{n}-{i}")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert c.stats()["size"] == 8 * 100


def test_client_caches_repeated_get(monkeypatch):
    """Client(cache=True) should fetch each unique URL only once."""
    from wpsecscan.http import Client

    call_count = {"n": 0}

    class FakeResp:
        status_code = 200
        text = "ok"
        content = b"ok"
        headers: dict = {}

    async def fake_request(self, method, url, follow_redirects=False, **kwargs):
        call_count["n"] += 1
        return FakeResp()

    import httpx

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    async def go():
        c = Client("https://example.com", cache=True)
        try:
            for _ in range(5):
                await c.get("/")
            assert call_count["n"] == 1
            for _ in range(3):
                await c.get("/wp-login.php")
            assert call_count["n"] == 2
            stats = c.cache_stats()
            assert stats["hits"] == (5 - 1) + (3 - 1)
            assert stats["size"] == 2
        finally:
            await c.aclose()

    asyncio.run(go())


def test_client_without_cache_fetches_every_time(monkeypatch):
    from wpsecscan.http import Client

    call_count = {"n": 0}

    class FakeResp:
        status_code = 200
        text = ""
        content = b""
        headers: dict = {}

    async def fake_request(self, method, url, follow_redirects=False, **kwargs):
        call_count["n"] += 1
        return FakeResp()

    import httpx

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    async def go():
        c = Client("https://example.com", cache=False)
        try:
            for _ in range(4):
                await c.get("/")
            assert call_count["n"] == 4
            assert c.cache_stats() is None
        finally:
            await c.aclose()

    asyncio.run(go())


def test_client_does_not_cache_post(monkeypatch):
    from wpsecscan.http import Client

    call_count = {"n": 0}

    class FakeResp:
        status_code = 200
        text = ""
        content = b""
        headers: dict = {}

    async def fake_request(self, method, url, follow_redirects=False, **kwargs):
        call_count["n"] += 1
        return FakeResp()

    import httpx

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    async def go():
        c = Client("https://example.com", cache=True)
        try:
            for _ in range(3):
                await c.post("/wp-login.php", data={"log": "x", "pwd": "y"})
            assert call_count["n"] == 3, "POST must never be served from cache"
        finally:
            await c.aclose()

    asyncio.run(go())
