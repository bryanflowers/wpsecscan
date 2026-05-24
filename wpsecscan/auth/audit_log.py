"""Append-only audit log with HMAC chaining.

Round-64 #117 — each entry stores a SHA-256 HMAC chained to the
previous entry. Tampering with any line breaks the chain forward, so
an attacker can't quietly remove a row.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _log_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "audit.log.jsonl"


def _hmac_key() -> bytes:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    key_path = home / ".audit-hmac-key"
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.is_symlink():
            key_path.unlink()
        key_path.write_bytes(os.urandom(32))
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return key_path.read_bytes()


def append(actor: str, action: str, target: str = "", details: dict | None = None) -> str:
    """Append an audit entry. Returns the entry's HMAC (proves it was written)."""
    p = _log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()

    # Read previous HMAC for chaining
    prev_hmac = ""
    if p.exists():
        try:
            with p.open("rb") as f:
                # Walk to the last line — small files, just read all
                lines = f.read().rstrip().splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    prev_hmac = last.get("hmac", "")
        except (OSError, ValueError):
            prev_hmac = ""

    entry = {
        "ts":      datetime.now(tz=timezone.utc).isoformat(),
        "actor":   actor,
        "action":  action,
        "target":  target,
        "details": details or {},
        "prev_hmac": prev_hmac,
    }
    payload = json.dumps(entry, sort_keys=True).encode("utf-8")
    h = hmac.new(_hmac_key(), payload, hashlib.sha256).hexdigest()
    entry["hmac"] = h

    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return h


def verify_chain() -> tuple[bool, int, str]:
    """Returns (is_valid, entries_checked, error_or_empty)."""
    p = _log_path()
    if not p.exists():
        return True, 0, ""
    try:
        lines = p.read_text(encoding="utf-8").rstrip().splitlines()
    except OSError as e:
        return False, 0, f"read error: {e}"
    prev_hmac = ""
    key = _hmac_key()
    for i, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except ValueError:
            return False, i, f"line {i}: not valid JSON"
        stored_hmac = entry.pop("hmac", None)
        if entry.get("prev_hmac", "") != prev_hmac:
            return False, i, f"line {i}: prev_hmac mismatch"
        expected = hmac.new(key, json.dumps(entry, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
        if expected != stored_hmac:
            return False, i, f"line {i}: HMAC mismatch (tampered or chain broken)"
        prev_hmac = stored_hmac
    return True, len(lines), ""
