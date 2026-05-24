"""Round-60 #9 — automatic remediation via WP REST + admin login.

OPT-IN ONLY. The user must explicitly pass --auto-remediate AND have
auth configured. Even then, we write zero changes unless the finding
matches one of a small allow-list of safe, single-step fixes.

Safe-fix allow-list (round-60 v1):

  - debug_leaks       → set WP_DEBUG=false via /wp-json/wpsecscan/v1/diag (companion plugin only)
  - exposed_files     → no auto-fix (manual delete required) — emits suggested commands
  - default_creds     → no auto-fix (manual rotation required)
  - rest_api          → no auto-fix
  - users (admin > 5) → no auto-fix
  - users.weak_pw     → no auto-fix
  - missing 2FA       → bulk-enable Two-Factor for admins (requires companion plugin v1.1+)
  - wp-config FILE_EDIT → set DISALLOW_FILE_EDIT (companion plugin)
  - update_core/plugin/theme available → trigger update via REST

For everything else we emit a "fix command" — a curl / wp-cli line the
user can run manually after reviewing.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse


SAFE_AUTO_FIX_CHECK_IDS = {
    "debug_leaks":               "Disable WP_DEBUG via companion plugin",
    "auth_modernisation":        "Force 2FA on admin accounts (companion plugin)",
    "rest_permission_audit":     "No auto-fix — review permission_callback manually",
}


def fixes_for(report: Any) -> list[dict]:
    """Walk the report and return a list of `{finding, fix_kind, command}` dicts.

    Each entry's `fix_kind` is one of:
      - "auto"   — safe automatic fix can be applied
      - "manual" — emit suggested command for the user to run
      - "skip"   — outside the auto-remediate allow-list
    """
    out: list[dict] = []
    d = report.to_dict() if hasattr(report, "to_dict") else (report or {})
    target = d.get("target", "")
    base = ""
    try:
        u = urlparse(target)
        base = f"{u.scheme}://{u.netloc}"
    except Exception:  # noqa: BLE001
        pass
    for r in d.get("results", []) or []:
        cid = r.get("check_id", "?")
        for f in r.get("findings", []) or []:
            kind, cmd = _classify(cid, f, base)
            out.append({"check_id": cid, "finding_title": f.get("title"),
                          "fix_kind": kind, "command": cmd})
    return out


def _classify(cid: str, finding: dict, base: str) -> tuple[str, str]:
    title = (finding.get("title") or "").lower()

    if cid == "debug_leaks":
        return ("auto", f"POST {base}/wp-json/wpsecscan/v1/set-config (WP_DEBUG=false)")
    if cid == "auth_modernisation" and "no 2fa" in title:
        return ("auto", f"POST {base}/wp-json/wpsecscan/v1/force-2fa-admins")
    if cid == "exposed_files":
        return ("manual", "rm wp-config.php.bak install.php .env .git ; restart php-fpm")
    if cid == "core_cves":
        return ("manual", f"wp core update --path=/var/www/html")
    if cid == "plugin_cves":
        slug = finding.get("extra", {}).get("plugin_slug", "") if isinstance(finding.get("extra"), dict) else ""
        return ("manual", f"wp plugin update {slug}".strip())
    if cid == "default_creds":
        return ("manual", "rotate the admin password + delete the default credential")
    return ("skip", "")


async def apply_auto_fixes(report: Any, *, companion_token: str | None = None,
                            dry_run: bool = True) -> list[dict]:
    """Apply every fix-kind=auto entry. Requires companion_token. dry_run=True
    is the default and ONLY simulates; pass dry_run=False to actually POST.

    Returns per-fix result list."""
    import httpx
    plan = [f for f in fixes_for(report) if f["fix_kind"] == "auto"]
    results = []
    if not companion_token or not plan:
        return [{**f, "status": "skipped (no companion token)" if not companion_token else "skipped (nothing to do)"}
                 for f in plan]
    d = report.to_dict() if hasattr(report, "to_dict") else (report or {})
    target = d.get("target", "")
    u = urlparse(target)
    base = f"{u.scheme}://{u.netloc}"

    async with httpx.AsyncClient(timeout=20.0,
                                    headers={"X-WPSecScan-Token": companion_token,
                                              "User-Agent": "WPSecScan/auto_remediation"}) as c:
        for f in plan:
            url = base + "/wp-json/wpsecscan/v1/" + (
                "set-config" if f["check_id"] == "debug_leaks" else
                "force-2fa-admins" if f["check_id"] == "auth_modernisation" else
                "noop"
            )
            if dry_run:
                results.append({**f, "status": "dry-run", "would_post": url})
                continue
            try:
                r = await c.post(url, json={"check_id": f["check_id"],
                                              "finding_title": f["finding_title"]})
                results.append({**f, "status": f"{r.status_code}",
                                  "body": (r.text or "")[:200]})
            except Exception as e:  # noqa: BLE001
                results.append({**f, "status": f"error: {type(e).__name__}",
                                  "body": str(e)[:200]})
    return results
