"""Multi-tenant scan namespacing.

Round-64 #120 — every scan + report carries a `tenant_id`. State is
filed under `~/.wpsecscan/tenants/<tenant_id>/`. Each tenant has its
own sites.json, vuln-db cache, history, etc.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _root() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def validate_tenant_id(tenant_id: str) -> str:
    if not _TENANT_RE.match(tenant_id):
        raise ValueError(
            f"Invalid tenant_id {tenant_id!r}; must match {_TENANT_RE.pattern}"
        )
    return tenant_id


def tenant_home(tenant_id: str) -> Path:
    validate_tenant_id(tenant_id)
    p = _root() / "tenants" / tenant_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_tenants() -> list[str]:
    base = _root() / "tenants"
    if not base.exists():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir() and _TENANT_RE.match(p.name))


def create_tenant(tenant_id: str) -> Path:
    p = tenant_home(tenant_id)
    # Create the canonical subdirs so downstream code can assume they exist
    for sub in ("sites", "reports", "history", "logs", "approvals"):
        (p / sub).mkdir(parents=True, exist_ok=True)
    return p


def delete_tenant(tenant_id: str) -> None:
    """Remove all tenant data. Destructive."""
    import shutil
    p = _root() / "tenants" / validate_tenant_id(tenant_id)
    if p.exists() and not p.is_symlink():
        shutil.rmtree(p)
