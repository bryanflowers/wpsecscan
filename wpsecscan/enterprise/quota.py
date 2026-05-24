"""Per-tenant scan-count quotas.

Round-64 #121 — track scan counts per tenant per UTC day. Used by
billing + by the daemon to reject over-quota requests.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .multi_tenant import tenant_home


def _today_key() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _quota_path(tenant_id: str) -> Path:
    return tenant_home(tenant_id) / "quota.json"


def get_usage(tenant_id: str) -> dict:
    p = _quota_path(tenant_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def consume(tenant_id: str, max_per_day: int) -> int:
    """Returns the new count for today. Raises if quota exceeded."""
    data = get_usage(tenant_id)
    today = _today_key()
    count = int(data.get(today, 0))
    if count >= max_per_day:
        raise PermissionError(f"Quota exceeded: {count}/{max_per_day} scans today for tenant {tenant_id}")
    data[today] = count + 1
    p = _quota_path(tenant_id)
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return count + 1


def reset_today(tenant_id: str) -> None:
    data = get_usage(tenant_id)
    data.pop(_today_key(), None)
    p = _quota_path(tenant_id)
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
