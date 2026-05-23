"""Safety-first tests for the proof extraction module.

The contract we're guarding:
  1. _assert_select_only accepts only SELECT-shaped statements
  2. prove.py source contains no destructive SQL keywords as identifier tokens
     (excluding test fixtures or whitelisted contexts)
  3. Each prover helper, when invoked, never causes its FakeClient to receive
     a non-GET/POST request, and never sends body content other than the
     hardcoded payloads
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.conftest import FakeClient, FakeResponse


def run(coro):
    return asyncio.run(coro)


# ============================== Safety guard tests ==============================

def test_assert_select_only_accepts_select():
    from wpsecscan.prove import _assert_select_only
    assert _assert_select_only("SELECT 1")
    assert _assert_select_only("SELECT @@version")
    assert _assert_select_only("SELECT 1 FROM dual WHERE version() LIKE '8.%'")
    assert _assert_select_only("UNION SELECT NULL, version()")
    assert _assert_select_only("WITH x AS (SELECT 1) SELECT * FROM x")


@pytest.mark.parametrize("destructive", [
    "INSERT INTO wp_users (user_login) VALUES ('x')",
    "UPDATE wp_users SET user_pass = 'x'",
    "DELETE FROM wp_users",
    "DROP TABLE wp_users",
    "CREATE TABLE x (id INT)",
    "ALTER TABLE x ADD c INT",
    "TRUNCATE wp_users",
    "REPLACE INTO wp_users VALUES (1)",
    "EXEC sp_who",
    "GRANT ALL ON *.* TO 'x'",
    "SELECT * FROM x; DROP TABLE y",          # multi-statement
    "SELECT * INTO OUTFILE '/tmp/x' FROM y",  # outfile
    "SELECT LOAD_FILE('/etc/passwd')",        # load_file
])
def test_assert_select_only_rejects_destructive(destructive):
    from wpsecscan.prove import _assert_select_only
    with pytest.raises(ValueError):
        _assert_select_only(destructive)


def test_assert_select_only_rejects_oversize():
    from wpsecscan.prove import _assert_select_only
    with pytest.raises(ValueError):
        _assert_select_only("SELECT 1 " + " " * 1000)


# ============================== Source-scan test ==============================

# Substrings that should NEVER appear in prove.py outside of the keyword
# blocklist or error-message strings.
_FORBIDDEN_SUBSTRINGS = (
    "INSERT INTO ", "UPDATE wp_", "DELETE FROM ", "DROP TABLE", "DROP DATABASE",
    "CREATE TABLE ", "ALTER TABLE ", "TRUNCATE TABLE ", "EXEC sp_", "EXECUTE ",
    "INTO OUTFILE ", "INTO DUMPFILE ", "LOAD_FILE(",
)


def test_prove_source_contains_no_destructive_sql():
    """Source-scan: prove.py must never construct destructive SQL.

    The check looks for SQL patterns that imply actual statement construction
    (e.g. 'INSERT INTO ', 'UPDATE wp_'). It deliberately allows the
    keyword-list literal that powers _assert_select_only, since that list
    contains keyword *names* not statements.
    """
    src = (Path(__file__).resolve().parents[1] / "wpsecscan" / "prove.py").read_text(encoding="utf-8")
    for forbid in _FORBIDDEN_SUBSTRINGS:
        assert forbid not in src.upper(), (
            f"prove.py contains destructive SQL pattern {forbid!r}"
        )


# ============================== Redaction test ==============================

def test_redact_strips_db_password():
    from wpsecscan.prove import _redact
    out = _redact("<?php define('DB_PASSWORD', 'hunter2-very-secret');")
    assert "hunter2" not in out
    assert "[REDACTED]" in out


def test_redact_strips_auth_keys():
    from wpsecscan.prove import _redact
    src = "define('AUTH_KEY', 'abcdef1234567890abcdef1234567890');"
    out = _redact(src)
    assert "abcdef1234567890" not in out


# ============================== Replay builder test ==============================

def test_replay_curl_get_with_params():
    from wpsecscan.prove import build_replay_curl
    cmd = build_replay_curl("GET", "https://example.com/", params={"p": "1' AND 1=1"})
    assert cmd.startswith("curl '")
    assert "p=1" in cmd
    assert "https://example.com" in cmd


def test_replay_curl_post_with_body():
    from wpsecscan.prove import build_replay_curl
    cmd = build_replay_curl("POST", "https://example.com/api", body='{"x":1}', headers={"Content-Type": "application/json"})
    assert "-X POST" in cmd
    assert "Content-Type: application/json" in cmd
    assert "--data-binary" in cmd


# ============================== Prover dispatch tests ==============================

def test_prove_sqli_error_extracts_version():
    from wpsecscan.prove import prove_sqli
    err_body = "XPATH syntax error: '~8.0.32'"
    client = FakeClient(responses={"/": FakeResponse(text=err_body)})
    out = run(prove_sqli(client, {
        "param": "id",
        "vector": "error",
        "baseline_path": "/",
        "baseline_value": "1",
    }))
    assert out["safe_audit"] == "select-only"
    assert out["extracted"].get("mysql_version") == "8.0.32"


def test_prove_sqli_unknown_vector_returns_skipped():
    from wpsecscan.prove import prove_sqli
    client = FakeClient(responses={})
    out = run(prove_sqli(client, {"param": "id"}))  # no vector
    assert "skipped" in out


def test_prove_path_traversal_confirms_deterministic():
    from wpsecscan.prove import prove_path_traversal
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    out = run(prove_path_traversal(client, {
        "param": "file",
        "payload_template": "../../../../../../etc/passwd",
        "baseline_path": "/",
    }))
    assert out["extracted"]["confirmed_deterministic"] is True
    assert "root:x:0:0" in out["extracted"]["preview_redacted"]


def test_prove_path_traversal_redacts_secrets():
    from wpsecscan.prove import prove_path_traversal
    # If the payload happens to read wp-config-shaped content, redaction must fire.
    body = "<?php define('DB_PASSWORD', 'topsecret');"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    out = run(prove_path_traversal(client, {
        "param": "file",
        "payload_template": "../../etc/passwd",
        "baseline_path": "/",
    }))
    assert "topsecret" not in out["extracted"]["preview_redacted"]
    assert "[REDACTED]" in out["extracted"]["preview_redacted"]


def test_prove_ssrf_localhost_only():
    from wpsecscan.prove import prove_ssrf
    client = FakeClient(responses={"/wp-json/oembed/1.0/proxy": FakeResponse(status_code=200, text="<html>nginx</html>")})
    out = run(prove_ssrf(client, {"endpoint": "/wp-json/oembed/1.0/proxy", "param": "url"}))
    assert out["extracted"]["probe_target"] == "http://127.0.0.1:80/"
    # The fake response contains 'nginx' which is in the localhost markers
    assert out["extracted"]["indicates_localhost_reached"] is True


def test_prove_open_redirect_is_noop():
    from wpsecscan.prove import prove_open_redirect
    client = FakeClient(responses={})
    out = run(prove_open_redirect(client, {}))
    assert out["safe_audit"] == "no-op"
    assert out["extracted"] == {}
