"""Detect publicly-open `?action=register` form, with FP filter for
intentional membership-plugin sites.

WordPress's "Anyone can register" setting flips this on. On a regular
blog/business site it's an attack vector — anonymous subscriber accounts
can probe authenticated endpoints, fill the database, exhaust mail
quotas, and provide a foothold for privilege escalation. On a
membership site (WooCommerce subscriptions, MemberPress, LearnDash) it's
intentional — we soften severity in that case.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_MEMBERSHIP_PLUGIN_MARKERS = (
    "memberpress", "membermouse", "wishlist-member",
    "paid-memberships-pro", "ultimate-member", "learndash",
    "lifterlms", "buddypress",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("probing /wp-login.php?action=register...")
    r = await client.get("/wp-login.php?action=register")
    if r is None or r.status_code != 200 or not r.text:
        return findings
    # Confirm we actually got a registration form
    if 'name="user_login"' not in r.text or "register" not in r.text.lower():
        return findings
    # Was a membership plugin detected by upstream checks?
    plugins: dict = ctx.get("shared", {}).get("plugins") or {}
    membership_present = any(
        any(tok in slug.lower() for tok in _MEMBERSHIP_PLUGIN_MARKERS)
        for slug in plugins
    )
    if membership_present:
        # Intentional registration — note for completeness, not alarm.
        findings.append(Finding(
            severity="info",
            title="Public registration enabled — membership plugin detected (likely intentional)",
            evidence=(
                "GET /wp-login.php?action=register returns the registration "
                "form (200), and an upstream check detected a membership/LMS "
                "plugin. This is the expected configuration; verify the role "
                "assigned to new registrations is `subscriber` not `editor`."
            ),
            remediation=(
                "Verify Settings → General → 'New User Default Role' is set to "
                "`Subscriber`. Avoid the temptation to default to `Editor` or "
                "`Author` for friction-free onboarding — privilege escalation "
                "from those roles is far easier than from Subscriber."
            ),
            url=client.url("/wp-login.php?action=register"),
        ))
        return findings
    findings.append(Finding(
        severity="medium",
        title="Public WordPress registration is open (no membership plugin detected)",
        evidence=(
            "GET /wp-login.php?action=register → HTTP 200 with the standard "
            "registration form. 'Anyone can register' is enabled in Settings → "
            "General. No membership/LMS plugin was detected to justify the open "
            "registration, so this is most likely a leftover from initial "
            "setup."
        ),
        remediation=(
            "Disable open registration: Settings → General → uncheck "
            "'Anyone can register'. Or via the CLI:\n"
            "  wp option update users_can_register 0\n"
            "Audit existing subscriber accounts for accounts you didn't create:\n"
            "  wp user list --role=subscriber"
        ),
        url=client.url("/wp-login.php?action=register"),
    ))
    return findings
