"""Regression: signatures with `_core` / `_global` slug must fire in aggressive mode.

The user reported wp-cron exposure stopped being detected. Root cause: the
signature engine only ran signatures matching plugin/theme slugs OR explicit
`scope: "global"` — leaving ~28 `_core` / `_global`-slugged signatures dead.

Two bugs were fixed:
  1. plugin_cves.check returned early when no plugins were detected, skipping
     all global signatures.
  2. The global-signature filter required explicit `scope: "global"` and missed
     the older `slug: "_core"` / `slug: "_global"` convention.
"""
from __future__ import annotations

import asyncio

from wpsecscan.checks.plugin_cves import check
from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def test_wp_cron_fires_with_no_plugins():
    """The original user complaint: wp-cron.php signature should fire even on a
    site where no plugins were enumerated, as long as aggressive mode is on."""
    client = FakeClient(responses={
        ("GET", "/wp-cron.php?doing_wp_cron"): FakeResponse(status_code=200, text=""),
    })
    ctx = {
        "target": "https://example.com",
        "aggressive": True,
        "shared": {"plugins": {}, "themes": {}},
        "step": lambda _s: None,
    }
    findings = _run(check(client, ctx))
    cron_findings = [f for f in findings if "wp-cron" in f.title.lower()]
    assert cron_findings, "wp-cron.php signature must fire when reachable"
    assert any(f.severity in ("low", "medium", "high", "critical") for f in cron_findings)


def test_install_php_fires_with_no_plugins():
    """Same path: install.php exposure (WPSX-INSTALL-PHP) is a _core signature.
    The signature is body_contains 'Welcome to the famous five-minute'."""
    client = FakeClient(responses={
        ("GET", "/wp-admin/install.php"): FakeResponse(
            status_code=200,
            text="Welcome to the famous five-minute WordPress installation process!"
        ),
    })
    ctx = {
        "target": "https://example.com",
        "aggressive": True,
        "shared": {"plugins": {}, "themes": {}},
        "step": lambda _s: None,
    }
    findings = _run(check(client, ctx))
    titles = [f.title.lower() for f in findings]
    assert any("install.php" in t for t in titles), \
        f"install.php signature must fire; got titles: {titles}"


def test_phpmyadmin_global_sig_fires():
    """phpMyAdmin probe is _core slug — must fire on aggressive even with no plugins."""
    client = FakeClient(responses={
        ("GET", "/phpmyadmin/"): FakeResponse(status_code=200, text=""),
    })
    ctx = {
        "target": "https://example.com",
        "aggressive": True,
        "shared": {"plugins": {}, "themes": {}},
        "step": lambda _s: None,
    }
    findings = _run(check(client, ctx))
    pma = [f for f in findings if "phpmyadmin" in f.title.lower()]
    assert pma, "phpMyAdmin signature must fire"


def test_no_signatures_fire_without_aggressive():
    """Without --aggressive, no signatures should run even if endpoints are reachable."""
    client = FakeClient(responses={
        ("GET", "/wp-cron.php?doing_wp_cron"): FakeResponse(status_code=200, text=""),
        ("GET", "/wp-admin/install.php"): FakeResponse(status_code=200, text=""),
    })
    ctx = {
        "target": "https://example.com",
        "aggressive": False,
        "shared": {"plugins": {}, "themes": {}},
        "step": lambda _s: None,
    }
    findings = _run(check(client, ctx))
    titles = [f.title.lower() for f in findings]
    assert not any("wp-cron" in t or "install.php" in t for t in titles), \
        "signatures must not fire without aggressive mode"


def test_inventory_no_dead_signatures():
    """No signature should be silently unreachable. Every signature must be
    either bound to a real-ish plugin/theme slug OR opt in to global execution
    (via scope=global OR slug starting with '_')."""
    import json
    from pathlib import Path
    sig_path = Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "exploit_signatures.json"
    sigs = json.loads(sig_path.read_text(encoding="utf-8"))["signatures"]
    real = [s for s in sigs if "id" in s]
    dead: list[str] = []
    for s in real:
        slug = (s.get("slug") or "").lower()
        scope = s.get("scope")
        if not slug:
            # Empty slug AND no scope = unreachable
            if scope != "global":
                dead.append(f"{s['id']} (no slug, no scope)")
            continue
        # slug-prefix convention OR explicit scope=global is fine
        if slug.startswith("_") or scope == "global":
            continue
        # Otherwise: relies on a plugin/theme being named exactly that slug.
        # This is fine — it's the normal case.
    assert not dead, f"unreachable signatures: {dead}"
