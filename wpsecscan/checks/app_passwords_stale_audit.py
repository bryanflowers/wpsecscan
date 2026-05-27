"""A8 (v2.6.0) — App Passwords stale-token audit.

The existing `app_passwords` check is passive (feature-on/off). This
sibling check runs ONLY when the scanner has authenticated session
data (cookies from authenticated.py OR a companion-plugin token), and
lists every user's stored Application Passwords with:

  • Age in days (>180 = stale, recommended for rotation).
  • last_used date if WP recorded it (the field exists since WP 6.2).
  • Whether the AP was created from an unusual user-agent (mobile,
    automation-tool, etc.) per the `name` field operators tend to set.

The output is a list of {user, name, age_days, last_used_days_ago}
findings, scored medium per stale AP.

Defaults to no-op without auth, so it's safe to keep in ALL_CHECKS.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..http import Client
from ..models import Finding


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        # WP returns ISO-8601 like "2024-11-15T03:21:00"
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00").split("+", 1)[0])
        return max(0, (datetime.now() - dt).days)
    except (ValueError, AttributeError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Skip when no auth context — runs only after authenticated.py succeeded
    # OR when the companion-plugin token is configured.
    has_session = bool(
        ctx.get("auth_cookies")
        or ctx.get("companion_token")
        or ctx.get("shared", {}).get("authenticated", False)
    )
    if not has_session:
        return findings

    step("App-Passwords stale audit: list users")
    r = await client.get("/wp-json/wp/v2/users?context=edit&per_page=100")
    if r is None or r.status_code != 200:
        return findings

    try:
        import json
        users = json.loads(r.text or "[]")
    except (ValueError, AttributeError):
        return findings

    if not isinstance(users, list):
        return findings

    for user in users:
        if not isinstance(user, dict):
            continue
        uid = user.get("id")
        name = user.get("name") or user.get("slug") or f"id={uid}"
        if uid is None:
            continue
        step(f"App-Passwords list for user {uid}")
        ar = await client.get(f"/wp-json/wp/v2/users/{uid}/application-passwords")
        if ar is None or ar.status_code != 200:
            continue
        try:
            aps = json.loads(ar.text or "[]")
        except (ValueError, AttributeError):
            continue
        if not isinstance(aps, list):
            continue
        for ap in aps:
            if not isinstance(ap, dict):
                continue
            ap_name = ap.get("name", "(unnamed)")
            created = ap.get("created")
            last_used = ap.get("last_used")
            age = _days_since(created)
            last = _days_since(last_used)

            is_stale_age = age is not None and age > 180
            is_unused = last is None or (last is not None and last > 90)

            if is_stale_age or (created and is_unused):
                sev = "medium" if (is_stale_age and is_unused) else "low"
                findings.append(Finding(
                    severity=sev,
                    title=f"Application Password stale: user '{name}' / token '{ap_name}'",
                    evidence=(
                        f"User: {name} (id={uid})\n"
                        f"AP name: {ap_name}\n"
                        f"Created: {created or 'unknown'}"
                        + (f" ({age} days ago)" if age is not None else "") + "\n"
                        f"Last used: {last_used or 'never recorded'}"
                        + (f" ({last} days ago)" if last is not None else "")
                    ),
                    remediation=(
                        f"1. Confirm with the user that this AP is still needed.\n"
                        f"2. If not, revoke at /wp-admin/profile.php → "
                        f"Application Passwords → Revoke.\n"
                        f"3. If still needed, rotate the token (revoke + reissue) "
                        f"and update the integration that uses it.\n"
                        f"4. Set an organisation policy: any AP unused for >90d "
                        f"is auto-revoked via wp-cron."
                    ),
                    url=client.url(f"/wp-json/wp/v2/users/{uid}/application-passwords"),
                    extra={"user_id": uid, "user_name": name,
                            "ap_name": ap_name, "age_days": age,
                            "last_used_days_ago": last},
                ))

    return findings
