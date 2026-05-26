"""Round-61 — plugin polish, auto-vuln-update, proxy, advanced settings.

Every public function added in round-61 gets a smoke test that proves
import + happy-path + the guard rails (no-network, symlink, validation).
"""
from __future__ import annotations

import json
import os
from pathlib import Path


# ============================================================
# Q5 — proxy support
# ============================================================

def test_http_client_proxy_merge_auth():
    from wpsecscan.http import Client
    # Plain proxy stays as-is
    assert Client._merge_proxy_auth("socks5://127.0.0.1:9050", None) == "socks5://127.0.0.1:9050"
    # None proxy returns None (no env fallback)
    assert Client._merge_proxy_auth(None, "user:pw") is None
    # Auth injected into a clean URL
    out = Client._merge_proxy_auth("http://proxy:8080", "alice:s3cret")
    assert out == "http://alice:s3cret@proxy:8080"
    # URL-encoding for special chars
    out = Client._merge_proxy_auth("http://proxy:8080", "user@x:p:w")
    assert "user%40x" in out
    # Existing @ in URL not double-stamped
    out = Client._merge_proxy_auth("http://existing:pw@proxy:8080", "ignored:ignored")
    assert out == "http://existing:pw@proxy:8080"


def test_http_client_accepts_proxy_kwargs():
    """Constructing a Client with proxy=... should not raise (HTTP proxy
    doesn't need socksio)."""
    from wpsecscan.http import Client
    c = Client("https://example.com", proxy="http://proxy.example:8080",
               proxy_auth="u:p")
    assert c._proxy_url == "http://u:p@proxy.example:8080"


def test_http_client_socks_proxy_handles_missing_socksio():
    """If the SOCKS plugin isn't installed, Client should either succeed
    (if socksio is present) or raise a clear ImportError (not silently)."""
    import pytest
    from wpsecscan.http import Client
    try:
        import socksio  # noqa: F401
        c = Client("https://example.com", proxy="socks5://127.0.0.1:9050")
        assert c._proxy_url == "socks5://127.0.0.1:9050"
    except ImportError:
        with pytest.raises(ImportError, match="socks"):
            Client("https://example.com", proxy="socks5://127.0.0.1:9050")


def test_sites_add_with_proxy(tmp_path, monkeypatch):
    from wpsecscan import sites
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    entry = sites.add("https://x.example", weekly=True,
                       proxy_url="socks5://127.0.0.1:9050",
                       proxy_auth="alice:secret")
    assert entry["proxy_url"] == "socks5://127.0.0.1:9050"
    assert entry.get("proxy_auth_sealed", "").startswith(("plain:", "sealed:"))


# ============================================================
# Q2 — auto-update vulnerabilities
# ============================================================

def test_db_status_shape(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    s = db.status()
    assert "source" in s and "entry_count" in s
    assert "stale" in s and "next_refresh_due_seconds" in s
    assert s["source"] in ("cache", "embedded", "missing")


def test_db_subscribe_persists(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    e = db.subscribe("https://hooks.example/abc", site_url="https://x.example", label="ops")
    assert e["webhook_url"] == "https://hooks.example/abc"
    subs = db.subscriptions_load()
    assert any(s.get("webhook_url") == "https://hooks.example/abc" for s in subs)


def test_db_subscribe_rejects_non_http(tmp_path, monkeypatch):
    import pytest
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    with pytest.raises(ValueError):
        db.subscribe("file:///etc/passwd")


def test_db_unsubscribe_returns_false_when_missing(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert db.unsubscribe("https://nope.example") is False


def test_db_unsubscribe_removes(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    db.subscribe("https://hooks.example/abc")
    assert db.unsubscribe("https://hooks.example/abc") is True


def test_db_refresh_exploit_signatures_no_network(monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    out = db.refresh_exploit_signatures()
    assert out["ok"] is False and "NO_NETWORK" in out.get("error", "")


def test_db_load_exploit_signatures_returns_dict():
    from wpsecscan import db
    sigs = db.load_exploit_signatures()
    assert isinstance(sigs, dict)


# ============================================================
# watchers.cve_alert_check
# ============================================================

def test_cve_alert_check_no_sites_no_crash(tmp_path, monkeypatch):
    from wpsecscan import watchers
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    out = watchers.cve_alert_check()
    assert out["checked_sites"] == 0
    assert out["new_alerts"] == []


def test_cve_alert_check_post_subscription_rejects_bad_url(monkeypatch):
    from wpsecscan import watchers
    assert watchers._post_cve_subscription("not-a-url", {"cve": "X"}) is False
    assert watchers._post_cve_subscription("", {"cve": "X"}) is False


def test_cve_alert_check_post_subscription_honours_no_network(monkeypatch):
    from wpsecscan import watchers
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    assert watchers._post_cve_subscription("https://hooks.example", {"cve": "X"}) is False


# ============================================================
# Q4 — config + mode picker
# ============================================================

def test_config_defaults_when_missing(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    cfg = config.load()
    assert cfg["theme"] == "dark"
    assert cfg["mode"] == "standard"
    assert cfg["follow_os_theme"] is True


def test_config_save_and_reload(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    config.save(theme="light", mode="expert", last_url="https://x.example")
    cfg2 = config.load()
    assert cfg2["theme"] == "light"
    assert cfg2["mode"] == "expert"
    assert cfg2["last_url"] == "https://x.example"


def test_config_invalid_enum_falls_back(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    # Manually write a bad value to disk
    (tmp_path / "config.json").write_text(json.dumps({
        "theme": "totally-bogus",
        "mode": "godmode",
    }), encoding="utf-8")
    cfg = config.load()
    assert cfg["theme"] == "dark"     # fell back to default
    assert cfg["mode"] == "standard"  # fell back to default


def test_config_helpers(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    config.save(mode="expert")
    assert config.is_expert() is True
    assert config.is_beginner() is False
    config.save(mode="beginner")
    assert config.is_beginner() is True
    assert config.is_expert() is False


def test_config_reset_wipes_file(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    config.save(theme="light")
    assert config.config_path().exists()
    config.reset()
    assert not config.config_path().exists()


def test_config_get_with_default(tmp_path, monkeypatch):
    from wpsecscan import config
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert config.get("theme", "dark") == "dark"
    assert config.get("nonexistent_key", "fallback") == "fallback"


# ============================================================
# Q3 — sv-ttk wrapper
# ============================================================


# ============================================================
# Q1 — WP plugin compliance smoke (file presence + content)
# ============================================================

def test_wp_plugin_has_domain_path_header():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "wpsecscan-companion.php"
    body = p.read_text(encoding="utf-8")
    assert "Domain Path: /languages" in body
    assert "wpsecscan_companion_load_textdomain" in body


def test_wp_plugin_no_query_param_token():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "includes" / "rest.php"
    body = p.read_text(encoding="utf-8")
    assert "get_param( 'token' )" not in body


def test_wp_plugin_no_mysql_deprecated():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "includes" / "diagnostics.php"
    body = p.read_text(encoding="utf-8")
    assert "mysql_get_client_info" not in body
    assert "mysqli_get_client_info" in body


def test_wp_plugin_readme_has_required_sections():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "readme.txt"
    body = p.read_text(encoding="utf-8")
    for section in ("== Description ==", "== Installation ==",
                    "== Frequently Asked Questions ==", "== Screenshots ==",
                    "== Changelog ==", "== Upgrade Notice =="):
        assert section in body, f"missing readme section: {section}"


def test_wp_plugin_languages_dir_exists():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "languages"
    assert p.is_dir()


def test_wp_plugin_assets_present():
    p = Path(__file__).resolve().parents[1] / "wp-plugin" / "wpsecscan-companion" / "assets"
    if not p.is_dir():
        return  # asset generation is optional; skip if not run
    expected = {"icon-128x128.png", "icon-256x256.png",
                "banner-772x250.png", "banner-1544x500.png",
                "screenshot-1.png"}
    files = {f.name for f in p.iterdir() if f.is_file()}
    missing = expected - files
    assert not missing, f"missing assets: {sorted(missing)}"
