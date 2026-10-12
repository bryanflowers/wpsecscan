"""v2.9.0 W0b — POST /scan consent + server-side target allowlist.

Handler-level: the real request handler class is driven with fake in-memory
request streams (no socket is bound) and `scanner.scan` is replaced by a
recorder, so nothing is scanned and no network is touched.
"""
from __future__ import annotations

import io
import json
import threading
import time

import pytest

from wpsecscan import api_server, scanner

TOKEN = "t" * 32


class _FakeReport:
    def to_dict(self) -> dict:
        return {"ok": True}


@pytest.fixture()
def recorder(monkeypatch, tmp_path):
    """Isolate env/home and replace scanner.scan with a kwargs recorder."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")
    monkeypatch.delenv("WPSECSCAN_OWNED_TARGETS", raising=False)
    monkeypatch.delenv("WPSECSCAN_API_ALLOWED_TARGETS", raising=False)
    calls: list[dict] = []
    called = threading.Event()

    async def fake_scan(target, **kwargs):
        calls.append({"target": target, **kwargs})
        called.set()
        return _FakeReport()

    monkeypatch.setattr(scanner, "scan", fake_scan)
    api_server._TASKS.clear()
    rec = type("Rec", (), {})()
    rec.calls = calls
    rec.called = called
    yield rec
    api_server._TASKS.clear()


def _post_scan(payload: dict, *, token: str = TOKEN) -> tuple[int, dict]:
    handler_cls = api_server._make_handler(TOKEN)
    h = handler_cls.__new__(handler_cls)
    raw = json.dumps(payload).encode("utf-8")
    h.headers = {"Authorization": f"Bearer {token}", "Content-Length": str(len(raw))}
    h.rfile = io.BytesIO(raw)
    h.wfile = io.BytesIO()
    h.path = "/scan"
    h.requestline = "POST /scan HTTP/1.1"
    h.request_version = "HTTP/1.1"
    h.command = "POST"
    h.client_address = ("127.0.0.1", 0)
    h.do_POST()
    head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body.decode("utf-8"))


def _wait_idle(task_id: str) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        with api_server._TASKS_LOCK:
            done = api_server._TASKS.get(task_id, {}).get("status") != "running"
        if done:
            break
        time.sleep(0.01)
    # the slot is released just after the task flips to done
    while time.time() < deadline and api_server._SCAN_SLOTS._value < api_server._API_MAX_CONCURRENT:
        time.sleep(0.01)


def test_aggressive_with_owned_true_needs_allowlist(recorder, monkeypatch):
    # v2.9.0 W0b: `owned:true` is client self-attestation, so it unlocks
    # aggressive mode only when the operator has set a server-side allowlist.
    # With the allowlist set and the target inside it, owned:true -> granted.
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", "example.com")
    status, resp = _post_scan({"target": "https://example.com", "aggressive": True, "owned": True})
    assert status == 202
    assert resp["consent"] == "granted"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["aggressive"] is True
    assert recorder.calls[0]["consent"] is True


def test_aggressive_with_owned_true_but_no_allowlist_is_downgraded(recorder):
    # Without an allowlist, owned:true from the request body is ignored; only
    # server-side consent (WPSECSCAN_OWNED_TARGETS / owned-targets file) counts.
    status, resp = _post_scan({"target": "https://example.com", "aggressive": True, "owned": True})
    assert status == 202
    assert resp["consent"] == "downgraded"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["consent"] is None


def test_aggressive_without_owned_is_downgraded(recorder):
    status, resp = _post_scan({"target": "https://example.com", "aggressive": True})
    assert status == 202
    assert resp["consent"] == "downgraded"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["consent"] is None


def test_owned_must_be_literal_true(recorder):
    status, resp = _post_scan({"target": "https://example.com", "aggressive": True, "owned": "yes"})
    assert status == 202
    assert resp["consent"] == "downgraded"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["consent"] is None


def test_env_owned_targets_grants_without_owned_field(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_OWNED_TARGETS", "1")
    status, resp = _post_scan({"target": "https://example.com", "aggressive": True})
    assert status == 202
    assert resp["consent"] == "granted"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["consent"] is None  # env decides inside scanner.scan


def test_non_aggressive_reports_consent_na(recorder):
    status, resp = _post_scan({"target": "https://example.com"})
    assert status == 202
    assert resp["consent"] == "n/a"
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["aggressive"] is False
    assert recorder.calls[0]["consent"] is None


def test_allowlist_blocks_foreign_host_before_scan(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", "example.com")
    status, resp = _post_scan({"target": "https://evil.test/", "aggressive": True, "owned": True})
    assert status == 403
    assert resp == {"error": "target not in WPSECSCAN_API_ALLOWED_TARGETS"}
    time.sleep(0.1)
    assert recorder.calls == []
    assert not api_server._TASKS
    assert api_server._SCAN_SLOTS._value == api_server._API_MAX_CONCURRENT


def test_allowlist_exact_host_allowed_and_subdomain_not(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", "example.com")
    status, _ = _post_scan({"target": "https://sub.example.com"})
    assert status == 403
    status, resp = _post_scan({"target": "https://EXAMPLE.com:8443/x"})
    assert status == 202
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])


def test_allowlist_wildcard_matches_subdomain(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", "other.org, *.example.com")
    status, resp = _post_scan({"target": "https://blog.example.com/"})
    assert status == 202
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])
    assert recorder.calls[0]["target"] == "https://blog.example.com/"
    # a lookalike that merely ends with the same text is not a subdomain
    status, _ = _post_scan({"target": "https://badexample.com/"})
    assert status == 403


def test_allowlist_unset_allows_any_target(recorder):
    status, resp = _post_scan({"target": "https://anything.test/"})
    assert status == 202
    assert recorder.called.wait(5)
    _wait_idle(resp["task_id"])


def test_allowlist_blank_value_is_treated_as_unset(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", "   ")
    assert api_server._allowed_targets() is None
    assert api_server._target_allowed("https://anything.test/") is True


def test_allowlist_with_no_usable_entry_denies_everything(recorder, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_API_ALLOWED_TARGETS", ",,")
    assert api_server._allowed_targets() == []
    assert api_server._target_allowed("https://example.com") is False


def test_bad_token_still_401(recorder):
    status, resp = _post_scan({"target": "https://example.com"}, token="wrong" * 8)
    assert status == 401
    assert recorder.calls == []


def test_openapi_documents_owned_field():
    schema = api_server._openapi_doc()["paths"]["/scan"]["post"]["requestBody"][
        "content"]["application/json"]["schema"]
    assert schema["properties"]["owned"] == {"type": "boolean"}
