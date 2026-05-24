"""RBAC for the daemon REST API.

Round-64 #116 — three roles, each granting a set of permissions:
  - Reader: view scans + reports
  - Operator: + start scans, manage sites
  - Admin: + manage users, settings, billing

Role storage at `~/.wpsecscan/rbac.json`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


# Permission strings. Adding new perms? Add to ALL_PERMISSIONS too.
PERM_VIEW_SCANS = "scans:view"
PERM_START_SCAN = "scans:start"
PERM_DELETE_SCAN = "scans:delete"
PERM_VIEW_SITES = "sites:view"
PERM_MANAGE_SITES = "sites:manage"
PERM_VIEW_REPORTS = "reports:view"
PERM_EXPORT_REPORTS = "reports:export"
PERM_MANAGE_USERS = "users:manage"
PERM_MANAGE_SETTINGS = "settings:manage"
PERM_MANAGE_BILLING = "billing:manage"

ALL_PERMISSIONS = {
    PERM_VIEW_SCANS, PERM_START_SCAN, PERM_DELETE_SCAN,
    PERM_VIEW_SITES, PERM_MANAGE_SITES,
    PERM_VIEW_REPORTS, PERM_EXPORT_REPORTS,
    PERM_MANAGE_USERS, PERM_MANAGE_SETTINGS, PERM_MANAGE_BILLING,
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "reader": {
        PERM_VIEW_SCANS, PERM_VIEW_SITES, PERM_VIEW_REPORTS,
    },
    "operator": {
        PERM_VIEW_SCANS, PERM_START_SCAN, PERM_VIEW_SITES, PERM_MANAGE_SITES,
        PERM_VIEW_REPORTS, PERM_EXPORT_REPORTS,
    },
    "admin": ALL_PERMISSIONS,
}


@dataclass
class User:
    username: str
    role: str

    def has(self, perm: str) -> bool:
        return perm in ROLE_PERMISSIONS.get(self.role, set())


def _store_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "rbac.json"


def load_users() -> dict[str, User]:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {u: User(username=u, role=r) for u, r in data.items()}


def save_users(users: dict[str, User]) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps({u: usr.role for u, usr in users.items()}, indent=2), encoding="utf-8")


def assign_role(username: str, role: str) -> None:
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"Unknown role {role!r}; valid: {list(ROLE_PERMISSIONS)}")
    users = load_users()
    users[username] = User(username=username, role=role)
    save_users(users)


def require(user: User | None, perm: str) -> None:
    if user is None or not user.has(perm):
        raise PermissionError(f"Permission required: {perm}")
