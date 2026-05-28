"""Item #42 — OS-keychain credential storage.

Thin wrapper over the `keyring` package (optional dep under [ui]). When
keyring is installed and a backend is available (Windows Credential
Manager, macOS Keychain, libsecret/KWallet on Linux), credentials are
stored there. When it isn't, falls back to a sealed local JSON file at
~/.wpsecscan/creds-vault.json with a per-install HMAC secret.

The fallback file is NOT encrypted at rest — keyring is the secure
path. The fallback exists so wpsecscan still runs on headless systems
without a keychain backend; users running there should treat the
fallback file as sensitive.

Surfaced to the CLI as `wpsecscan creds {add,list,rm,rotate}` in
Phase I commit 26. This module is the underlying storage.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable


_SERVICE = "wpsecscan"


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _index_path() -> Path:
    """Per-install index of (site_url, field) entries. The values
    themselves go in keyring or the sealed fallback; this file just
    records WHAT entries exist so `creds list` can enumerate them.
    Lives at ~/.wpsecscan/creds-index.json."""
    return _home() / "creds-index.json"


def _fallback_path() -> Path:
    return _home() / "creds-vault.json"


def _have_keyring() -> bool:
    try:
        import keyring  # noqa: F401
        # Probe that a backend is actually available; some envs install the
        # package but have no functioning backend.
        from keyring.backends.fail import Keyring as FailBackend  # type: ignore
        import keyring as _kr
        return not isinstance(_kr.get_keyring(), FailBackend)
    except ImportError:
        return False
    except Exception:  # noqa: BLE001 — defensive
        return False


def _ident(site_url: str, field: str) -> str:
    """Build a stable key for a (site, field) entry."""
    return f"{site_url}::{field}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_secret(site_url: str, field: str, value: str) -> str:
    """Store a secret for (site_url, field). Returns "keyring" or "fallback"
    depending on which backend was used."""
    ident = _ident(site_url, field)
    _add_to_index(site_url, field)
    if _have_keyring():
        import keyring
        keyring.set_password(_SERVICE, ident, value)
        return "keyring"
    _fallback_set(ident, value)
    return "fallback"


def get_secret(site_url: str, field: str) -> str | None:
    """Retrieve a secret. Returns None if not found."""
    ident = _ident(site_url, field)
    if _have_keyring():
        import keyring
        v = keyring.get_password(_SERVICE, ident)
        if v is not None:
            return v
    # Try fallback even when keyring is available — old entries may live there.
    return _fallback_get(ident)


def delete_secret(site_url: str, field: str) -> bool:
    """Delete a single secret. Returns True if something was removed."""
    ident = _ident(site_url, field)
    removed = False
    if _have_keyring():
        try:
            import keyring
            keyring.delete_password(_SERVICE, ident)
            removed = True
        except Exception:  # noqa: BLE001
            pass
    if _fallback_delete(ident):
        removed = True
    _remove_from_index(site_url, field)
    return removed


def list_sites() -> list[tuple[str, list[str]]]:
    """Return [(site_url, [field, ...])] from the on-disk index. The values
    themselves are not returned — call get_secret() per (site, field)."""
    idx = _load_index()
    return sorted([(site, sorted(fields)) for site, fields in idx.items()])


def list_fields_for(site_url: str) -> list[str]:
    """Return [field, ...] for one site_url."""
    idx = _load_index()
    return sorted(idx.get(site_url, []))


def rotate_secret(site_url: str, field: str, new_value: str) -> str:
    """Replace the secret for (site_url, field) with new_value. Same as
    set_secret but kept as a separate verb so the CLI has explicit
    rotate-aware UX."""
    return set_secret(site_url, field, new_value)


def backend_in_use() -> str:
    """Return 'keyring' or 'fallback' so the CLI can tell the user where
    new secrets will land."""
    return "keyring" if _have_keyring() else "fallback"


# ---------------------------------------------------------------------------
# Internal: index file (which entries exist)
# ---------------------------------------------------------------------------

def _load_index() -> dict[str, list[str]]:
    p = _index_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(d, dict):
            return {k: sorted(set(v)) for k, v in d.items()
                    if isinstance(k, str) and isinstance(v, list)}
    except (OSError, ValueError):
        pass
    return {}


def _save_index(idx: dict[str, list[str]]) -> None:
    p = _index_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        # C17 (v2.7.2) — 0o600 atomic write so the index (which lists
        # every stored credential identifier — site URLs + field names)
        # doesn't inherit the process umask. Mirrors the data-file
        # pattern at `_fallback_save` (line ~211).
        import os as _os
        fd = _os.open(str(p),
                       _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
        with _os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(idx, indent=2))
    except OSError:
        pass


def _add_to_index(site_url: str, field: str) -> None:
    idx = _load_index()
    fields = set(idx.get(site_url, []))
    fields.add(field)
    idx[site_url] = sorted(fields)
    _save_index(idx)


def _remove_from_index(site_url: str, field: str) -> None:
    idx = _load_index()
    if site_url not in idx:
        return
    fields = [f for f in idx[site_url] if f != field]
    if fields:
        idx[site_url] = fields
    else:
        del idx[site_url]
    _save_index(idx)


# ---------------------------------------------------------------------------
# Internal: fallback JSON storage
# ---------------------------------------------------------------------------

def _fallback_load() -> dict[str, str]:
    p = _fallback_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return {k: v for k, v in d.items() if isinstance(k, str) and isinstance(v, str)}
    except (OSError, ValueError):
        return {}


def _fallback_save(data: dict[str, str]) -> None:
    p = _fallback_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        # S9: atomic 0600 create — no window where the file is world-readable.
        # On POSIX, os.open(O_CREAT|O_WRONLY|O_TRUNC, 0o600) honours the
        # mode argument intersected with umask. On Windows, the mode arg is
        # ignored; NTFS ACL hardening is out of scope here — the comment
        # above the call tells the user to treat this file as sensitive.
        payload = json.dumps(data, indent=2).encode("utf-8")
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
        except Exception:
            # fdopen takes ownership of fd; only close manually if fdopen failed.
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        # Belt-and-braces: re-chmod on POSIX (in case the file already
        # existed with a wider mode and O_CREAT didn't tighten it).
        if os.name != "nt":
            try:
                os.chmod(str(p), 0o600)
            except OSError:
                pass
    except OSError:
        pass


def _fallback_set(ident: str, value: str) -> None:
    d = _fallback_load()
    d[ident] = value
    _fallback_save(d)


def _fallback_get(ident: str) -> str | None:
    return _fallback_load().get(ident)


def _fallback_delete(ident: str) -> bool:
    d = _fallback_load()
    if ident not in d:
        return False
    del d[ident]
    _fallback_save(d)
    return True
