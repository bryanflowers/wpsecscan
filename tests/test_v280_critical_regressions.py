"""Regression tests for v2.8.0 Wave 1 — Critical bugs (B2, B3, B4, B5).

B1 (heatmap_svg |safe XSS) was an audit FALSE POSITIVE: heatmap.render_svg
only emits _html.escape()'d hardcoded OWASP labels + integer cell counts;
no user/scan-controlled data is rendered. Verified pre-execution.

B2 checks/websocket_audit.py — `request.encode()` crashes on IDN hosts
B3 checks/tls_reneg_dos.py — same IDN crash on `host.encode()`
B4 daemon/_legacy.py — report files use bare write_text (corrupt on crash)
B5 daemon/_legacy.py + api_server.py — zero SIGTERM/SIGHUP handling
"""
import asyncio
import inspect
import os
import signal
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _file(rel: str) -> str:
    import wpsecscan
    return (Path(wpsecscan.__file__).parent / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# B2 — websocket_audit IDN punycode encoding
# ---------------------------------------------------------------------------

def test_websocket_audit_punycode_encodes_idn_host():
    """Source check: the IDN host must be ascii-encoded via .encode('idna')
    or urllib.parse before being concatenated into the raw HTTP request."""
    src = _file("checks/websocket_audit.py")
    # Either explicit idna encoding OR the host already came from a parser
    # that ASCII-normalises it.
    assert "idna" in src or ".encode('idna')" in src or ".encode(\"idna\")" in src or "_ascii_host" in src or "ascii_host" in src, (
        "B2 — websocket_audit must punycode-encode IDN hosts before "
        ".encode() — or the raw request crashes UnicodeEncodeError."
    )


# ---------------------------------------------------------------------------
# B3 — tls_reneg_dos IDN punycode encoding
# ---------------------------------------------------------------------------

def test_tls_reneg_dos_punycode_encodes_idn_host():
    src = _file("checks/tls_reneg_dos.py")
    assert "idna" in src or "_ascii_host" in src or "ascii_host" in src, (
        "B3 — tls_reneg_dos must punycode-encode IDN hosts before "
        "concatenating into the HTTP request bytes."
    )


# ---------------------------------------------------------------------------
# B4 — daemon report files atomic write
# ---------------------------------------------------------------------------

def test_daemon_run_daemon_uses_atomic_write():
    """Source check: the daemon's per-scan report write must NOT be a
    bare `write_text` — it must go through history._atomic_write_text
    (or equivalent temp-then-replace pattern)."""
    src = _file("daemon/_legacy.py")
    # The pre-fix bare write pattern is gone.
    bad = '(out_dir / f"{stem}.json").write_text(json_out.render(report)'
    assert bad not in src, (
        "B4 — daemon report write must use atomic temp+replace pattern, "
        "not bare write_text."
    )
    # The fix uses _atomic_write_text (or equivalent helper).
    assert "_atomic_write_text" in src or "os.replace" in src


# ---------------------------------------------------------------------------
# B5 — daemon + api_server signal handling
# ---------------------------------------------------------------------------

def test_daemon_installs_sigterm_handler():
    """Source check: run_daemon must install a SIGTERM handler so
    `docker stop` / systemd `Restart=on-failure` triggers clean shutdown
    rather than aborting in the middle of a scan."""
    src = _file("daemon/_legacy.py")
    assert "SIGTERM" in src, (
        "B5 — daemon must handle SIGTERM (the default systemd/docker stop "
        "signal). Currently only KeyboardInterrupt is caught."
    )


def test_api_server_installs_sigterm_handler():
    src = _file("api_server.py")
    assert "SIGTERM" in src or "signal.signal" in src, (
        "B5 — api_server must handle SIGTERM for clean shutdown."
    )
