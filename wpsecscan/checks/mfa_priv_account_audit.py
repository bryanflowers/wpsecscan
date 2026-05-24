"""MFA audit on privileged accounts (companion-plugin assisted).

Round-64 #63 — every administrator + editor account should have MFA
(WebAuthn / TOTP / hardware key) enabled. There's no way to enumerate
this from the outside, so this check calls
/wp-json/wpsecscan-companion/v1/mfa-status which the companion plugin
exposes. The plugin returns: [{user_id, login, role, mfa_enabled,
mfa_method}]. We flag any administrator without MFA.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PRIV_ROLES = ("administrator", "editor", "super_admin", "shop_manager")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("querying companion plugin for MFA status...")
    r = await client.get("/wp-json/wpsecscan-companion/v1/mfa-status")
    if r is None or r.status_code == 404:
        return findings  # plugin not installed
    if r.status_code in (401, 403):
        findings.append(
            Finding(
                severity="info",
                title="Companion plugin MFA-status endpoint requires auth",
                evidence=f"GET /wp-json/wpsecscan-companion/v1/mfa-status -> {r.status_code}",
                remediation="Configure the companion shared secret in wpsecscan sites config.",
                url=client.url("/wp-json/wpsecscan-companion/v1/mfa-status"),
            )
        )
        return findings
    if r.status_code != 200:
        return findings

    try:
        data = r.json()
    except (ValueError, TypeError):
        return findings

    users = data.get("users", []) if isinstance(data, dict) else []
    if not isinstance(users, list):
        return findings

    no_mfa_priv: list[dict] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        role = (u.get("role") or "").lower()
        if role not in _PRIV_ROLES:
            continue
        if not u.get("mfa_enabled"):
            no_mfa_priv.append(u)

    if no_mfa_priv:
        for u in no_mfa_priv:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Privileged account without MFA: {u.get('login', '?')} ({u.get('role', '?')})",
                    evidence=f"User {u.get('login', '?')} (id {u.get('user_id', '?')}) — role {u.get('role', '?')} — MFA disabled",
                    remediation=(
                        "Enable MFA on every administrator/editor account. Top WP MFA plugins:\n"
                        "  - WP 2FA (recommended; supports WebAuthn + TOTP + recovery codes)\n"
                        "  - Two Factor (core team plugin)\n"
                        "  - Wordfence Login Security\n"
                        "Enforce MFA at the role level (admin can't login without it)."
                    ),
                    url=client.url("/wp-admin/users.php"),
                    extra={"user": u.get("login"), "role": u.get("role"), "user_id": u.get("user_id")},
                )
            )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"All {len(users)} accounts in priv roles have MFA enabled (good)",
                evidence=f"Checked {len(users)} accounts; 0 priv accounts without MFA",
                remediation="Re-run after any new admin/editor account is added.",
                url=client.url("/wp-json/wpsecscan-companion/v1/mfa-status"),
            )
        )

    return findings
