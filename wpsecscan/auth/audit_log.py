"""Append-only audit log with HMAC chaining.

Round-64 #117 — each entry stores a SHA-256 HMAC chained to the
previous entry. Tampering with any line breaks the chain forward, so
an attacker can't quietly remove a row.

v2.7.3 (N20-partial / Wave 5) — `audit_log.append()` is now wired
into the auth-sensitive code paths in `creds_vault.set_secret` /
`delete_secret` and `marketplace_v27` install / verify. Before
v2.7.3 the module had ZERO production callsites — the audit trail
the module was designed to provide didn't exist at runtime.

To record an action, callers should use `safe_append(action,
target, details)` which derives the actor automatically from
WPSECSCAN_ACTOR / getpass.getuser() and swallows any exception
from the underlying append (audit failures must not break the
operation being audited).
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
        # C3 (v2.7.2) — atomic O_CREAT|O_EXCL with mode 0o600 so there
        # is no window between create-and-chmod where another local
        # user could read the freshly-written HMAC key.
        try:
            fd = os.open(str(key_path),
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # Another process raced us to create it; just read theirs.
            return key_path.read_bytes()
        with os.fdopen(fd, "wb") as fh:
            fh.write(os.urandom(32))
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


def _default_actor() -> str:
    """Best-effort actor for audit entries when the caller doesn't
    supply one. Order: WPSECSCAN_ACTOR env > $USER / $USERNAME >
    getpass.getuser() > 'cli'."""
    actor = os.environ.get("WPSECSCAN_ACTOR", "").strip()
    if actor:
        return actor[:64]
    actor = (os.environ.get("USER") or os.environ.get("USERNAME") or "").strip()
    if actor:
        return actor[:64]
    try:
        import getpass
        return (getpass.getuser() or "cli")[:64]
    except Exception:  # noqa: BLE001
        return "cli"


def safe_append(action: str, target: str = "", details: dict | None = None,
                  *, actor: str | None = None) -> None:
    """Convenience wrapper for production code. Derives the actor when
    not supplied, swallows any exception from the append (an audit
    failure must NOT break the operation being audited — e.g. a
    creds_vault.set_secret call should succeed even if the audit log
    file is unwriteable).

    Production code paths SHOULD prefer this over `append()` directly."""
    try:
        append(actor or _default_actor(), action, target, details or {})
    except Exception:  # noqa: BLE001
        pass


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
        # C2 (v2.7.2) — constant-time compare so an attacker who can
        # append entries to the log and re-run verify_chain can't
        # extract a valid HMAC byte-by-byte from the timing of the
        # mismatch error.
        if not hmac.compare_digest(expected, stored_hmac or ""):
            return False, i, f"line {i}: HMAC mismatch (tampered or chain broken)"
        prev_hmac = stored_hmac
    return True, len(lines), ""
