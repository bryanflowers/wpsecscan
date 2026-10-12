"""v2.9.0 W0b — daemon targets config carries `owned: true` into scan(consent=...).

`daemon/_legacy.py` used to pass `aggressive=bool(t.get("aggressive"))` straight
from the targets config with no ownership consent. Now `owned: true` maps to
`consent=True`, anything else to `consent=None`, and a target that asks for
aggressive mode without consent gets exactly one startup warning.
"""
from __future__ import annotations

import asyncio
import json
import signal

import pytest

from wpsecscan.daemon import _legacy


class _StopDaemon(Exception):
    """Raised by the fake asyncio.sleep to end run_daemon's loop after one pass."""


@pytest.fixture(autouse=True)
def _clean_consent_env(monkeypatch, tmp_path):
    monkeypatch.delenv("WPSECSCAN_OWNED_TARGETS", raising=False)
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")


TARGETS = [
    {"url": "https://owned.example.com", "schedule": "* * * * *",
     "aggressive": True, "owned": True},
    {"url": "https://unowned.example.org", "schedule": "* * * * *",
     "aggressive": True},
    {"url": "https://passive.example.net", "schedule": "* * * * *",
     "aggressive": False},
]


def _write_config(tmp_path, targets):
    cfg = tmp_path / "targets.json"  # JSON is accepted when pyyaml is absent
    cfg.write_text(json.dumps({"targets": targets, "out_dir": str(tmp_path / "out")}),
                   encoding="utf-8")
    return cfg


def test_consent_for_maps_only_literal_true():
    assert _legacy._consent_for({"owned": True}) is True
    assert _legacy._consent_for({}) is None
    assert _legacy._consent_for({"owned": False}) is None
    assert _legacy._consent_for({"owned": "true"}) is None
    assert _legacy._consent_for({"owned": 1}) is None


def test_load_config_parses_owned_key(tmp_path):
    cfg = _legacy._load_config(_write_config(tmp_path, TARGETS))
    assert [t.get("owned") for t in cfg["targets"]] == [True, None, None]


def test_warns_once_for_unowned_aggressive_only():
    lines: list[str] = []
    n = _legacy._warn_unconsented_aggressive(TARGETS, log=lines.append)
    assert n == 1
    assert len(lines) == 1
    assert "unowned.example.org" in lines[0]
    assert "aggressive requested without owned:true" in lines[0]
    assert "will run passive" in lines[0]


def test_passive_target_produces_no_warning():
    lines: list[str] = []
    assert _legacy._warn_unconsented_aggressive([TARGETS[2]], log=lines.append) == 0
    assert lines == []


def test_no_warning_when_env_grants_consent(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_OWNED_TARGETS", "unowned.example.org")
    lines: list[str] = []
    assert _legacy._warn_unconsented_aggressive(TARGETS, log=lines.append) == 0
    assert lines == []


def test_default_log_goes_to_stderr(capsys):
    _legacy._warn_unconsented_aggressive([TARGETS[1]])
    err = capsys.readouterr().err
    assert err.count("WARNING") == 1
    assert "unowned.example.org" in err


def test_run_daemon_passes_consent_and_warns_once(tmp_path, monkeypatch, capsys):
    cfg = _write_config(tmp_path, TARGETS)
    calls: list[dict] = []

    async def fake_scan(url, **kw):
        calls.append({"url": url, **kw})
        raise RuntimeError("stop after recording")  # caught by run_daemon's per-scan handler

    async def fake_sleep(_s):
        raise _StopDaemon

    import wpsecscan.scanner as scanner_mod
    monkeypatch.setattr(scanner_mod, "scan", fake_scan)
    monkeypatch.setattr(_legacy, "_acquire_pid_file", lambda: tmp_path / "daemon.pid")
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    # run_daemon falls back to signal.signal() on Windows; restore afterwards.
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM,)}
    try:
        with pytest.raises(_StopDaemon):
            asyncio.run(_legacy.run_daemon(cfg))
    finally:
        for s, h in saved.items():
            signal.signal(s, h)

    by_url = {c["url"]: c for c in calls}
    assert set(by_url) == {t["url"] for t in TARGETS}
    assert by_url["https://owned.example.com"]["aggressive"] is True
    assert by_url["https://owned.example.com"]["consent"] is True
    assert by_url["https://unowned.example.org"]["aggressive"] is True
    assert by_url["https://unowned.example.org"]["consent"] is None
    assert by_url["https://passive.example.net"]["aggressive"] is False
    assert by_url["https://passive.example.net"]["consent"] is None

    err = capsys.readouterr().err
    assert err.count("aggressive requested without owned:true") == 1
    assert "unowned.example.org" in err
    assert "owned.example.com: aggressive" not in err
    assert "passive.example.net: aggressive" not in err
