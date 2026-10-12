"""v2.9.0 regression tests for the F821 / SyntaxError class of bug.

* host_recon: a non-empty severity bucket used to raise NameError (`label`).
* reporters: three modules had 3.12-only nested same-type quotes in f-strings
  (SyntaxError on 3.10/3.11) -- importing them is the gate.
* gui_windows: needs tkinter + a display to run, so only a static check here.
"""
from __future__ import annotations

import ast
import asyncio
import importlib
from pathlib import Path

import pytest


def test_host_recon_nonempty_bucket_does_not_raise(monkeypatch):
    mod = importlib.import_module("wpsecscan.checks.host_recon")
    # Only Redis (6379, high) and Docker HTTP (2375, critical) are "open".
    monkeypatch.setattr(mod, "_tcp_connect", lambda host, port, timeout=2.0: port in (6379, 2375))
    ctx = {"target": "https://example.invalid/"}
    findings = asyncio.run(mod.check(None, ctx))
    by_sev = {f.severity: f for f in findings}
    assert set(by_sev) == {"critical", "high"}
    assert "tcp/2375  Docker daemon HTTP (no TLS)" in by_sev["critical"].evidence
    assert "tcp/6379  Redis (typically auth-less)" in by_sev["high"].evidence


@pytest.mark.parametrize("modname", [
    "wpsecscan.reporters.exec_pdf",
    "wpsecscan.reporters.auditor_pdf",
    "wpsecscan.reporters.attestation",
    "wpsecscan.reporters.issue_export",
    "wpsecscan.checks.host_recon",
    "wpsecscan.checks.graphql_field_authz_deep",
    "wpsecscan.checks.cloudflare_origin_leak",
])
def test_modules_import(modname):
    importlib.import_module(modname)


def test_cloudflare_apex_strips_www_prefix_only():
    mod = importlib.import_module("wpsecscan.checks.cloudflare_origin_leak")
    assert mod._apex("www.foo.co.uk") == "foo.co.uk"
    # lstrip("www.") used to eat leading w/. characters: "web.example.com" -> "eb.example.com"
    assert mod._apex("web.example.com") == "example.com"
    assert mod._apex("www.wwwidgets.com") == "wwwidgets.com"


def test_gui_windows_defines_accent():
    # Static: tkinter/display not required. Module-level ACCENT must exist.
    src = (Path(__file__).parent.parent / "wpsecscan" / "gui_windows.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    names = {t.id for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name)}
    assert "ACCENT" in names
