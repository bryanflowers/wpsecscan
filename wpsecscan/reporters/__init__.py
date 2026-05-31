"""Reporters package — output backends for ScanReport.

v2.8.1 B39 — shared atomic-write helper. Pre-v2.8.1 every reporter
used bare `path.write_text(...)`; a SIGTERM or crash mid-write left
a torn file (often the operator's only deliverable). This mirrors
`history._atomic_write_text` — write to a pid-suffixed temp file
then atomically promote via `os.replace`.

Use it from any reporter's write/render path:

    from . import _atomic_write_text
    _atomic_write_text(out_path, json_blob)
"""
from __future__ import annotations

import os
from pathlib import Path


def _atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Atomic temp+rename write. Same contract as Path.write_text but
    no torn-file window. Caller's responsibility to ensure the parent
    directory exists (mkdir parents=True if you can't guarantee it)."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(text, encoding=encoding)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomic byte-write variant for binary reporters (PDF, XLSX, etc.)."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
