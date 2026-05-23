"""Tests for the 4 new aggressive-detection checks.

Avoids any literal webshell strings in test bodies — Windows Defender quarantines
files containing real eval+base64_decode patterns. We assemble those at runtime
from harmless fragments instead.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

from tests.conftest import FakeClient, FakeResponse


async def _no_sleep(_s):
    return None


def run(coro):
    return asyncio.run(coro)


# Reconstruct the backdoor marker at runtime so AV doesn't quarantine this file
_BACKDOOR_FRAG_EVAL_B64 = "ev" + "al(" + "base64_" + "decode"
_BACKDOOR_FRAG_EVAL_POST = "ev" + "al($_" + "POST"


# wpgraphql

def test_wpgraphql_not_present():
    from wpsecscan.checks.wpgraphql import check
    client = FakeClient(responses={})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("not detected" in f.title.lower() for f in findings)


def test_wpgraphql_introspection_flagged():
    from wpsecscan.checks.wpgraphql import check
    client = FakeClient(responses={})

    async def post_router(path, **kwargs):
        body = kwargs.get("content") or ""
        if "__typename" in body:
            return FakeResponse(text='{"data":{"__typename":"RootQuery"}}')
        if "__schema" in body and "types" in body:
            return FakeResponse(text='{"data":{"__schema":{"types":[{"name":"User"}]}}}')
        return FakeResponse(text='{"data":{}}')

    client.post = post_router
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("introspection is enabled" in f.title.lower() for f in findings)


# ajax_surface

def test_ajax_surface_discovers_action_names():
    from wpsecscan.checks.ajax_surface import check
    home_body = (
        '<script>'
        'jQuery.post(ajaxurl, {action: "plugin_foo_handler"});'
        'jQuery.post(ajaxurl, {"action": "wpforms_submit"});'
        '</script>'
    )
    client = FakeClient(responses={})

    async def get_router(path, **kwargs):
        if path == "/wp-admin/admin-ajax.php":
            params = kwargs.get("params") or {}
            action = params.get("action")
            if action == "plugin_foo_handler":
                return FakeResponse(text='{"data":"sensitive"}')
            return FakeResponse(text="0")
        if path == "/":
            return FakeResponse(text=home_body)
        return None

    client.get = get_router
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))
    summary = next((f for f in findings if "action(s) discovered" in f.title), None)
    assert summary is not None
    assert "plugin_foo_handler" in summary.evidence


# backup_exposure

def test_backup_exposure_flags_updraft_log():
    from wpsecscan.checks.backup_exposure import check
    client = FakeClient(responses={
        "/wp-content/updraft/log.log": FakeResponse(
            text="2024-01-01 backup started\nupdraftplus\n",
            headers={"content-type": "text/plain"},
        ),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("UpdraftPlus" in f.title for f in findings if f.severity != "info")


def test_backup_exposure_flags_critical_dump():
    from wpsecscan.checks.backup_exposure import check
    client = FakeClient(responses={
        "/database.sql": FakeResponse(
            content=b"-- MySQL dump\nCREATE TABLE wp_users",
            headers={"content-type": "application/sql"},
        ),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "critical" and "database dump" in f.title.lower() for f in findings)


def test_backup_exposure_clean():
    from wpsecscan.checks.backup_exposure import check
    client = FakeClient(responses={})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("No backup-plugin exposure" in f.title for f in findings)


# core_tampering — use the reconstructed string so the file doesn't trip AV
def test_core_tampering_flags_webshell_in_uploads():
    from wpsecscan.checks.core_tampering import check
    suspicious_php = ("<?php " + _BACKDOOR_FRAG_EVAL_B64 + "('xxx'));").encode()
    client = FakeClient(responses={
        "/wp-content/uploads/sh" + "ell.php": FakeResponse(
            content=suspicious_php,
            headers={"content-type": "application/x-php"},
        ),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "critical" and "sh" + "ell.php" in f.title for f in findings)


def test_core_tampering_bumps_severity_on_backdoor_markers():
    from wpsecscan.checks.core_tampering import check
    suspicious_php = "<?php " + _BACKDOOR_FRAG_EVAL_POST + "['x']);"
    client = FakeClient(responses={
        "/wp-content/mu-plugins/loader.php": FakeResponse(text=suspicious_php),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "critical" and "loader.php" in f.title for f in findings)


def test_core_tampering_clean_when_no_suspects():
    from wpsecscan.checks.core_tampering import check
    client = FakeClient(responses={})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("No suspicious core-tampering paths" in f.title for f in findings)


# Counts

def test_check_count_grew():
    from wpsecscan.checks import ALL_CHECKS
    assert len(ALL_CHECKS) >= 37


def test_payload_count_grew():
    from wpsecscan.payloads import load_payloads
    ps = load_payloads()
    assert len(ps) >= 110


def test_signature_count_grew():
    from pathlib import Path
    import json
    sig_path = Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "exploit_signatures.json"
    data = json.loads(sig_path.read_text(encoding="utf-8"))
    assert len(data["signatures"]) >= 40
