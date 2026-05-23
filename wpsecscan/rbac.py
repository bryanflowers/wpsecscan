"""M36 Role-based access control.

For multi-user environments (shared scanning host, API server). Defines three
roles:
  - reader:  can fetch reports / history, cannot trigger scans
  - scanner: + can trigger passive scans
  - admin:   + can trigger aggressive scans, edit users, edit risk weights

Users + their bcrypt-hashed API tokens are stored in ~/.wpsecscan/users.json:
  {"alice": {"role": "admin",  "token_hash": "$2b$12$..."},
   "bob":   {"role": "scanner","token_hash": "$2b$12$..."}}

bcrypt is optional — falls back to sha256 with a per-user salt if bcrypt
isn't installed. Bcrypt is the recommended path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

ROLES = ("reader", "scanner", "admin")

# Permission → role required
PERMISSIONS = {
    "fetch_report":       "reader",
    "trigger_scan":       "scanner",
    "trigger_aggressive": "admin",
    "edit_users":         "admin",
    "edit_risk_weights":  "admin",
}


def _path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "users.json"


def _load() -> dict:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        # Best-effort chmod 600 on POSIX
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _hash_token(token: str, salt: str) -> str:
    try:
        import bcrypt
        return "bcrypt$" + bcrypt.hashpw(token.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    except ImportError:
        # sha256-with-salt fallback
        h = hashlib.sha256((salt + token).encode("utf-8")).hexdigest()
        return f"sha256${salt}${h}"


def _verify_token(token: str, stored: str) -> bool:
    if stored.startswith("bcrypt$"):
        try:
            import bcrypt
            return bcrypt.checkpw(token.encode("utf-8"), stored[7:].encode("ascii"))
        except ImportError:
            return False
    if stored.startswith("sha256$"):
        try:
            _, salt, h = stored.split("$", 2)
        except ValueError:
            return False
        return hmac.compare_digest(h, hashlib.sha256((salt + token).encode("utf-8")).hexdigest())
    return False


def create_user(username: str, role: str) -> str:
    """Create a new user with the given role. Returns the plaintext token
    (caller must show ONCE then discard)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    users = _load()
    if username in users:
        raise ValueError(f"user {username!r} already exists")
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(8)
    users[username] = {"role": role, "token_hash": _hash_token(token, salt)}
    _save(users)
    return token


def delete_user(username: str) -> bool:
    users = _load()
    if username not in users:
        return False
    del users[username]
    _save(users)
    return True


def list_users() -> list[dict]:
    """Return [{"username", "role"}, ...]. Never exposes token hashes."""
    return [{"username": u, "role": v.get("role", "reader")}
            for u, v in sorted(_load().items())]


def authenticate(username: str, token: str) -> str | None:
    """Return role if (username, token) is valid, else None."""
    users = _load()
    entry = users.get(username)
    if not entry:
        return None
    stored = entry.get("token_hash", "")
    return entry.get("role") if _verify_token(token, stored) else None


def has_permission(role: str, permission: str) -> bool:
    """Roles are ordered reader < scanner < admin. Unknown role or permission
    defaults to deny — never raise."""
    needed = PERMISSIONS.get(permission)
    if needed is None or role not in ROLES:
        return False
    return ROLES.index(role) >= ROLES.index(needed)
