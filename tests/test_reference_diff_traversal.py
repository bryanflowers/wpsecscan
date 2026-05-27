"""Regression test for B3: reference_diff.build_reference_manifest must
reject zip/tar archives with path-traversal or symlink entries.

Before the fix, build_reference_manifest called extractall() unconditionally.
A crafted reference archive could write outside the temp dir.
"""
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from wpsecscan import reference_diff


def _build_traversal_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("wordpress/wp-config.php", b"<?php // legit\n")
        zf.writestr("../../escape.txt", b"PWNED")  # ← traversal


def _build_traversal_tar(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        legit = tarfile.TarInfo(name="wordpress/wp-config.php")
        legit.size = 4
        tf.addfile(legit, io.BytesIO(b"foo\n"))
        evil = tarfile.TarInfo(name="../../escape.txt")  # ← traversal
        evil.size = 5
        tf.addfile(evil, io.BytesIO(b"PWNED"))


def _build_symlink_tar(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        legit = tarfile.TarInfo(name="wordpress/index.php")
        legit.size = 4
        tf.addfile(legit, io.BytesIO(b"foo\n"))
        sym = tarfile.TarInfo(name="wordpress/danger.php")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        tf.addfile(sym)


def test_zip_traversal_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    archive = tmp_path / "evil.zip"
    _build_traversal_zip(archive)
    with pytest.raises(ValueError, match="traversal"):
        reference_diff.build_reference_manifest(archive, "test")


def test_tar_traversal_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    archive = tmp_path / "evil.tar.gz"
    _build_traversal_tar(archive)
    with pytest.raises(ValueError, match="traversal"):
        reference_diff.build_reference_manifest(archive, "test")


def test_tar_symlink_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    archive = tmp_path / "evil-sym.tar.gz"
    _build_symlink_tar(archive)
    with pytest.raises(ValueError, match="symlink"):
        reference_diff.build_reference_manifest(archive, "test")


def test_legit_zip_works(tmp_path, monkeypatch):
    """A normal WordPress-shaped zip must still extract + manifest."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    archive = tmp_path / "wordpress.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("wordpress/wp-config-sample.php", b"<?php\n// hello\n")
        zf.writestr("wordpress/wp-load.php", b"<?php\n// loader\n")
    manifest = reference_diff.build_reference_manifest(archive, "test")
    assert "wp-config-sample.php" in manifest
    assert "wp-load.php" in manifest
    assert len(manifest["wp-config-sample.php"]) == 64  # sha256 hex
