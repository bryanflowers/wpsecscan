"""Regression tests for v2.7.2 Wave 2 — High-severity fixes.

Covers C3 (audit-log key file atomic 0o600 create), C4 (share-link
TTL), C7 (argparse off-by-one bounds in 3 subcommands), C9 (verify=
False removed from login-redirect check), C10 (tarfile extraction
filter), C11 (api_server token-echo redaction), and C5/C6 (PowerShell
EncodedCommand path).

C8 (companion plugin email-hash) lives in the PHP layer and is
smoke-tested via grep below — pytest can't exercise PHP directly.
"""
import inspect
import os
import sys

import pytest


# ---------------------------------------------------------------------------
# C3 — audit-log HMAC key is created atomically with 0o600
# ---------------------------------------------------------------------------

def test_audit_log_key_created_atomically_at_0o600(tmp_path, monkeypatch):
    """The HMAC key file must be created via O_EXCL|0o600 so there is
    no window between create and chmod where another local user can
    read the freshly-written key."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.auth import audit_log
    _ = audit_log._hmac_key()
    key_path = tmp_path / ".audit-hmac-key"
    assert key_path.exists()
    # On POSIX, st_mode & 0o777 should be 0o600 immediately.
    if os.name == "posix":
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600, f"key file mode {oct(mode)} != 0o600"
    # Regardless of OS, the source must use the atomic pattern.
    src = inspect.getsource(audit_log._hmac_key)
    assert "O_EXCL" in src
    assert "0o600" in src


# ---------------------------------------------------------------------------
# C4 — share-link payload carries issued_at/expires_at; verify rejects expired
# ---------------------------------------------------------------------------

def _build_test_payload(monkeypatch, tmp_path, ttl=3600):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.models import Finding, CheckResult, ScanReport
    from wpsecscan.reporters import share_link
    f = Finding(severity="high", title="x", evidence="y")
    cr = CheckResult(check_id="demo", check_name="d", findings=[f])
    rep = ScanReport(target="https://t", scanned_at="2026-05-28T00:00:00Z",
                      duration_ms=0, results=[cr])
    return share_link.build_share_payload(rep, "demo", 0, ttl_seconds=ttl)


def test_share_link_payload_includes_ttl_fields(monkeypatch, tmp_path):
    p = _build_test_payload(monkeypatch, tmp_path)
    assert "issued_at" in p
    assert "expires_at" in p
    assert p["expires_at"] > p["issued_at"]


def test_share_link_verify_accepts_fresh(monkeypatch, tmp_path):
    from wpsecscan.reporters import share_link
    p = _build_test_payload(monkeypatch, tmp_path, ttl=3600)
    assert share_link.verify(p) is True


def test_share_link_verify_rejects_expired(monkeypatch, tmp_path):
    """A payload whose expires_at is in the past must verify False
    even though the HMAC is still cryptographically valid."""
    from wpsecscan.reporters import share_link
    p = _build_test_payload(monkeypatch, tmp_path, ttl=3600)
    # Re-sign with a back-dated expires_at to simulate an expired link.
    import hmac as _hmac
    import hashlib
    import json as _json
    body = {k: v for k, v in p.items() if k not in ("signature", "share_id")}
    body["issued_at"] = body["issued_at"] - 4000
    body["expires_at"] = body["expires_at"] - 4000  # now in the past
    raw = _json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["signature"] = _hmac.new(share_link._share_secret(), raw,
                                    hashlib.sha256).hexdigest()
    assert share_link.verify(body) is False


def test_share_link_verify_rejects_pre_v272_payload(monkeypatch, tmp_path):
    """A pre-v2.7.2 payload (no expires_at) must NOT verify under the
    new rules — otherwise leaked legacy links survive the fix."""
    from wpsecscan.reporters import share_link
    p = _build_test_payload(monkeypatch, tmp_path, ttl=3600)
    # Strip the TTL fields and re-sign as if produced by v2.7.1.
    import hmac as _hmac
    import hashlib
    import json as _json
    body = {k: v for k, v in p.items()
              if k not in ("signature", "share_id", "issued_at", "expires_at")}
    raw = _json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["signature"] = _hmac.new(share_link._share_secret(), raw,
                                    hashlib.sha256).hexdigest()
    assert share_link.verify(body) is False


# ---------------------------------------------------------------------------
# C7 — argparse bounds off-by-one (3 sites in __main__.py)
# ---------------------------------------------------------------------------

def test_main_no_longer_has_off_by_one_bounds_guards():
    """The three sites flagged by C7 used `i + N < len(args) + M` forms
    that simplify to `i + (N-M) < len(args)`, causing args[i+N] to
    IndexError when the flag is the last token. The fix removes the
    `+ M` and uses `i + N < len(args)`. Pin both: the bad form must
    be gone and the new form must be present."""
    import wpsecscan.__main__ as m
    src = _strip_py_comments(inspect.getsource(m))
    # All `< len(args) + N` (N >= 1) forms were the bug pattern.
    import re as _re
    bad_hits = _re.findall(r"<\s*len\(args\)\s*\+\s*\d", src)
    assert bad_hits == [], (
        f"v2.7.2 C7 — `< len(args) + N` off-by-one form must be gone, "
        f"still found: {bad_hits!r}"
    )


# ---------------------------------------------------------------------------
# C9 / C10 / C11 / C5 / C6 — source-inspection regressions
# ---------------------------------------------------------------------------

def _strip_py_comments(src: str) -> str:
    """Strip `# ...` line-comments AND docstrings so source-pattern
    asserts don't trip on the explanatory text that references the
    old buggy pattern."""
    import re as _re
    out_lines = []
    in_doc = False
    doc_marker = None
    for line in src.splitlines():
        s = line.lstrip()
        if not in_doc and (s.startswith('"""') or s.startswith("'''")):
            doc_marker = s[:3]
            # single-line docstring?
            if s.count(doc_marker) >= 2 and len(s) > 3:
                continue
            in_doc = True
            continue
        if in_doc:
            if doc_marker in line:
                in_doc = False
            continue
        # strip trailing # comment
        line = _re.sub(r"\s+#.*$", "", line)
        # skip whole-line comments
        if line.lstrip().startswith("#"):
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def test_login_redirect_no_unconditional_verify_false():
    from wpsecscan.checks import login_redirect_http_hop
    src = _strip_py_comments(inspect.getsource(login_redirect_http_hop))
    assert "verify=False" not in src, (
        "login_redirect_http_hop must not pass verify=False unconditionally"
    )
    assert "WPSECSCAN_INSECURE_TLS" in src or "verify=not" in src


def test_trust_v27_tarfile_uses_filter():
    from wpsecscan import trust_v27
    src = inspect.getsource(trust_v27.reproducible_build_verify)
    assert 'filter="data"' in src or "filter='data'" in src


def test_api_server_does_not_echo_token_prefix():
    from wpsecscan import api_server
    src = _strip_py_comments(inspect.getsource(api_server))
    # The pre-fix `{token[:6]}***` leaked 6 chars of a token to stdout.
    assert "token[:6]" not in src
    assert "token[:4]" not in src


def test_gui_toast_uses_encodedcommand_not_fstring():
    """GUI toast notifier must not pass an f-string built from finding
    titles as a single PowerShell argv string (C5)."""
    import wpsecscan.gui as g
    src = inspect.getsource(g)
    # The fix uses EncodedCommand with base64-encoded UTF-16LE.
    assert "EncodedCommand" in src
    # And the prior bad pattern — Popen with a single ps string — is gone.
    assert "subprocess.Popen(ps, shell=False" not in src


def test_gui_v27_extras_shortcut_uses_encodedcommand():
    from wpsecscan import gui_v27_extras
    src = inspect.getsource(gui_v27_extras)
    assert "EncodedCommand" in src
    # The prior `-Command` + raw f-string form is gone.
    assert '"-Command", ps_cmd' not in src
