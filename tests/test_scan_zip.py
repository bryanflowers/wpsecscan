"""Wave 3 — unit tests for wpsecscan/scan_zip.py.

Complements the security-pinning at tests/test_reference_diff_traversal.py
by exercising scan_zip's pattern detector + zip-bomb + symlink defences.
"""
import io
import zipfile
from pathlib import Path

import pytest

from wpsecscan import scan_zip


def _zip_with(tmp_path: Path, name: str, files: dict[str, bytes]) -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        for n, body in files.items():
            zf.writestr(n, body)
    return p


def test_clean_plugin_only_info(tmp_path):
    p = _zip_with(tmp_path, "clean.zip", {
        "myplugin/myplugin.php":
            b"<?php /* Plugin Name: My\nTested up to: 6.7\nRequires PHP: 7.4\n*/ ?>"
            b"<?php echo 'hello';",
    })
    rep = scan_zip.scan_zip(p)
    sevs = {f.severity for r in rep.results for f in r.findings}
    # Only info (the 'no suspicious patterns' marker)
    assert sevs == {"info"}


def test_eval_chain_flagged_high(tmp_path):
    p = _zip_with(tmp_path, "evil.zip", {
        "evil/evil.php": b"<?php eval(base64_decode('cGhwaW5mbygpOw=='));",
    })
    rep = scan_zip.scan_zip(p)
    sevs = [f.severity for r in rep.results for f in r.findings]
    assert "high" in sevs


def test_assert_request_flagged_critical(tmp_path):
    p = _zip_with(tmp_path, "ar.zip", {
        "x/x.php": b"<?php assert($_REQUEST['cmd']);",
    })
    rep = scan_zip.scan_zip(p)
    sevs = [f.severity for r in rep.results for f in r.findings]
    assert "critical" in sevs


def test_traversal_entry_blocks_extraction(tmp_path):
    p = tmp_path / "trav.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../escape.php", b"<?php // pwned ?>")
        zf.writestr("ok.php", b"<?php // legit ?>")
    rep = scan_zip.scan_zip(p)
    titles = [f.title for r in rep.results for f in r.findings]
    assert any("Path-traversal" in t for t in titles)
    # ok.php must NOT have been scanned (extraction was blocked)
    assert not any("ok.php" in t for t in titles)


def test_zip_bomb_blocked(tmp_path):
    """A zip whose declared uncompressed size exceeds 200 MB is rejected."""
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        # 250 MB of zeros compresses tiny but the file_size field exposes it.
        zf.writestr("bomb.txt", b"\0" * (250 * 1024 * 1024))
    rep = scan_zip.scan_zip(p)
    titles = [f.title for r in rep.results for f in r.findings]
    assert any("Zip-bomb" in t for t in titles)


def test_plugin_header_missing_fields(tmp_path):
    """A plugin file missing 'Tested up to:' or 'Requires PHP:' is flagged low."""
    p = _zip_with(tmp_path, "plug.zip", {
        "plug/plug.php":
            b"<?php /* Plugin Name: Plug */ ?><?php echo 'ok';",
    })
    rep = scan_zip.scan_zip(p)
    titles = [f.title for r in rep.results for f in r.findings]
    assert any("Tested up to" in t for t in titles)
    assert any("Requires PHP" in t for t in titles)
