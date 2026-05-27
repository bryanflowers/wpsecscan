"""Wave 3 — tests for wpsecscan/reference_diff.py beyond the security
regression at tests/test_reference_diff_traversal.py."""
import json
import zipfile
from pathlib import Path

import pytest

from wpsecscan import reference_diff


def test_diff_added_removed_modified():
    live = {"wp-load.php": "abc", "wp-content/themes/x/x.php": "xxx",
            "evil.php": "deadbeef"}
    ref  = {"wp-load.php": "abc", "wp-includes/foo.php": "f"}
    d = reference_diff.diff_against_reference(live, ref, include_content=True)
    assert any(r["path"] == "evil.php" for r in d["added"])
    assert any(r["path"] == "wp-includes/foo.php" for r in d["removed"])
    # No modifications since wp-load.php hashes match


def test_diff_modified_detected():
    live = {"wp-load.php": "DIFFERENT"}
    ref  = {"wp-load.php": "abc"}
    d = reference_diff.diff_against_reference(live, ref)
    assert any(r["path"] == "wp-load.php" for r in d["modified"])


def test_diff_skips_mutable_by_default():
    """wp-content/ + wp-config.php differences are hidden without --include-content."""
    live = {"wp-content/plugins/p/p.php": "x", "wp-config.php": "y", "wp-load.php": "z"}
    ref  = {"wp-load.php": "z"}
    d = reference_diff.diff_against_reference(live, ref)
    # Only wp-load.php is shared; the added entries are inside the mutable prefixes
    assert d["added"] == []
    d2 = reference_diff.diff_against_reference(live, ref, include_content=True)
    assert len(d2["added"]) == 2


def test_load_live_manifest_canonical_shape(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"files": {"a.php": "h1", "b.php": "h2"}}),
                  encoding="utf-8")
    m = reference_diff.load_live_manifest(p)
    assert m == {"a.php": "h1", "b.php": "h2"}


def test_load_live_manifest_flat_shape(tmp_path):
    """Legacy flat-dict shape still parses."""
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a.php": "h1"}), encoding="utf-8")
    m = reference_diff.load_live_manifest(p)
    assert m == {"a.php": "h1"}


def test_load_reference_manifest_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert reference_diff.load_reference_manifest("does-not-exist") == {}


def test_build_reference_zip_caches(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    archive = tmp_path / "wp.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("wordpress/wp-load.php", b"hello world\n")
    manifest = reference_diff.build_reference_manifest(archive, "test-99")
    assert "wp-load.php" in manifest
    assert len(manifest["wp-load.php"]) == 64

    # Subsequent call loads from cache
    cached = reference_diff.load_reference_manifest("test-99")
    assert cached == manifest
