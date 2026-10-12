"""v2.9.0 — marketplace default index moved to raw.githubusercontent.com; the
trust boundary must stay the repo path, not the whole raw host."""
from __future__ import annotations

from wpsecscan import marketplace, marketplace_v27

RAW = "https://raw.githubusercontent.com/bryanflowers/wpsecscan/main/docs/marketplace.json"


def test_default_index_urls_point_at_repo_file():
    assert marketplace.DEFAULT_REMOTE_URL == RAW
    assert marketplace_v27._INDEX_URL == RAW


def test_raw_host_trusted_only_within_repo_path(monkeypatch):
    monkeypatch.setattr(marketplace_v27, "_INDEX_URL", RAW)
    ok, _ = marketplace_v27._safe_source_url(
        "https://raw.githubusercontent.com/bryanflowers/wpsecscan/main/checks/x.py")
    assert ok is True
    ok, reason = marketplace_v27._safe_source_url(
        "https://raw.githubusercontent.com/attacker/evil/main/x.py")
    assert ok is False
    assert "outside" in reason


def test_list_prints_no_entries_message(monkeypatch, capsys):
    monkeypatch.setattr(marketplace_v27, "_fetch_index", lambda **_k: {"_version": 1, "entries": []})
    marketplace_v27.cmd_marketplace(["list"])
    assert marketplace.NO_ENTRIES_MESSAGE in capsys.readouterr().out
