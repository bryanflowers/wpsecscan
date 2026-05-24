"""Auto-isolation when a critical finding fires.

Round-64 #174 — when a `critical` finding is detected, ask the
companion plugin to drop a strict `.htaccess` deny rule (or equivalent
nginx rule) for a short period (default 60 minutes) while a human
triages. Strict consent gate: WPSECSCAN_AUTO_ISOLATE=1 +
target in sites list.

Same consent pattern as `exploit_verify.py`.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx


def _consent_check(target: str) -> tuple[bool, str]:
    """Returns (ok, reason)."""
    if os.environ.get("WPSECSCAN_AUTO_ISOLATE") != "1":
        return False, "WPSECSCAN_AUTO_ISOLATE=1 not set"
    # Sites-list check (target must be in user's configured sites)
    try:
        from .. import sites as sites_mod
        owned = {s.get("url", "").rstrip("/") for s in sites_mod.list_sites()}
        target_clean = target.rstrip("/")
        if target_clean not in owned:
            return False, f"target {target_clean!r} not in sites list"
    except (ImportError, AttributeError):
        return False, "could not load sites list"
    return True, ""


async def request_isolation(target: str, *, minutes: int = 60, reason: str = "WPSecScan critical finding") -> dict:
    """Asks the companion plugin to drop a deny rule.

    Returns {"ok": bool, "message": str, "expires_at": str}.
    """
    ok, why = _consent_check(target)
    if not ok:
        return {"ok": False, "message": f"consent denied: {why}"}

    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(
            f"{base}/wp-json/wpsecscan-companion/v1/quarantine",
            json={"minutes": minutes, "reason": reason},
        )
        if r.status_code in (200, 202):
            try:
                return r.json()
            except ValueError:
                return {"ok": True, "message": "isolated", "expires_at": ""}
        return {"ok": False, "message": f"companion returned {r.status_code}"}


async def lift_isolation(target: str) -> dict:
    ok, why = _consent_check(target)
    if not ok:
        return {"ok": False, "message": f"consent denied: {why}"}
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.delete(f"{base}/wp-json/wpsecscan-companion/v1/quarantine")
        if r.status_code in (200, 204):
            return {"ok": True, "message": "isolation lifted"}
        return {"ok": False, "message": f"companion returned {r.status_code}"}


# Sample .htaccess the companion would write (for reference):
#
#   # Inserted by WPSecScan auto-isolation at <timestamp>; expires <timestamp>
#   <RequireAll>
#     Require ip 203.0.113.0/24
#     # Whitelist the admin IP here so triage is still possible
#   </RequireAll>
#
# Or nginx:
#
#   allow 203.0.113.0/24;
#   deny all;
