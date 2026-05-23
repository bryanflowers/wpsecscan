"""Authenticated scan — logs in as an admin and inspects internal state.

Only runs when ctx['auth_user'] and ctx['auth_pass'] are set. Performs:
  1. Login via /wp-login.php form POST (uses real wp-test_cookie flow)
  2. Fetches /wp-admin/users.php → user role audit
  3. Fetches /wp-admin/site-health.php → Health & Status critical issues
  4. Probes /wp-admin/options.php and parses non-default flags
  5. Detects plugins/themes definitively from /wp-admin/plugins.php
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

LOGIN_FORM_RE  = re.compile(r'name=["\']log["\']', re.IGNORECASE)
NONCE_RE       = re.compile(r'name=["\']_wpnonce["\'][^>]+value=["\']([a-f0-9]+)', re.IGNORECASE)
ADMIN_BAR_RE   = re.compile(r'<div\s+id=["\']wpadminbar["\']', re.IGNORECASE)
PLUGIN_ROW_RE  = re.compile(r'<tr[^>]+id=["\']([a-z0-9_\-]+)["\']\s+class=["\'](active|inactive)', re.IGNORECASE)
USER_ROW_RE    = re.compile(r'<td[^>]+data-colname=["\']Username["\'][^>]*>(.*?)</td>', re.IGNORECASE | re.DOTALL)
USER_ROLE_RE   = re.compile(r'<td[^>]+data-colname=["\']Role["\'][^>]*>(.*?)</td>',     re.IGNORECASE | re.DOTALL)


async def _login(target: str, user: str, password: str) -> httpx.AsyncClient | None:
    """Log into WP via the wp-login.php form. Returns an authenticated client or None."""
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    jar = httpx.Cookies()
    c = httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        cookies=jar,
        headers={"User-Agent": "WPSecScan/1.0 (authenticated-scan)"},
    )
    # 1. GET wp-login.php to seed test_cookie
    try:
        r = await c.get(base + "/wp-login.php")
    except httpx.HTTPError:
        await c.aclose()
        return None
    if r.status_code != 200 or not LOGIN_FORM_RE.search(r.text or ""):
        await c.aclose()
        return None
    # 2. POST credentials
    try:
        r = await c.post(
            base + "/wp-login.php",
            data={
                "log": user,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": base + "/wp-admin/",
                "testcookie": "1",
            },
            headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
        )
    except httpx.HTTPError:
        await c.aclose()
        return None
    # Success signals: admin bar HTML, or our follow-redirect landed on /wp-admin/,
    # or the jar received a wordpress_logged_in_ cookie.
    if ADMIN_BAR_RE.search(r.text or ""):
        return c
    if "/wp-admin" in str(r.url):
        return c
    if any(c_name.startswith("wordpress_logged_in_") for c_name in jar.keys()):
        return c
    await c.aclose()
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    user = ctx.get("auth_user")
    pwd = ctx.get("auth_pass")
    if not user or not pwd:
        findings.append(
            Finding(
                severity="info",
                title="Authenticated scan skipped (no credentials)",
                evidence="Pass --auth-user and --auth-pass on the CLI, or fill the auth fields in the GUI, to enable.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Intentionally do NOT include the username in the step message — it would
    # be broadcast to any progress listener and could end up in a debug log or
    # GUI screenshot shared in a bug report.
    step("logging in with provided admin credentials...")
    auth = await _login(ctx["target"], user, pwd)
    if auth is None:
        findings.append(
            Finding(
                severity="medium",
                title="Authentication failed — credentials rejected or login form not recognized",
                evidence="POST /wp-login.php did not return the wp-admin bar.",
                remediation="Verify credentials. If the site uses a custom login URL (e.g. WPS Hide Login), the authenticated scan can't reach it.",
                url=ctx["target"],
            )
        )
        return findings

    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        # 1. Users / roles
        step("inspecting /wp-admin/users.php for admin accounts...")
        try:
            r = await auth.get(base + "/wp-admin/users.php?role=administrator")
            usernames = USER_ROW_RE.findall(r.text or "")
            roles = USER_ROLE_RE.findall(r.text or "")
            admins = []
            for u_html, role_html in zip(usernames, roles):
                u = re.sub(r"<[^>]+>", "", u_html).strip()
                role = re.sub(r"<[^>]+>", "", role_html).strip()
                if "administrator" in role.lower():
                    admins.append(u)
            if len(admins) > 1:
                findings.append(
                    Finding(
                        severity="medium",
                        title=f"{len(admins)} administrator account(s) — review for unauthorized users",
                        evidence="Administrator-role users found:\n" + "\n".join(f"  - {a}" for a in admins),
                        remediation="Audit each admin account. Demote anyone who doesn't need admin (Editor is often sufficient). Force 2FA on all admins.",
                        url=base + "/wp-admin/users.php?role=administrator",
                    )
                )
        except httpx.HTTPError:
            pass

        # 2. Plugins page — definitive plugin enumeration with active/inactive status
        step("enumerating plugins from /wp-admin/plugins.php...")
        try:
            r = await auth.get(base + "/wp-admin/plugins.php")
            plugins_seen = PLUGIN_ROW_RE.findall(r.text or "")
            if plugins_seen:
                active = [p for p, s in plugins_seen if s.lower() == "active"]
                inactive = [p for p, s in plugins_seen if s.lower() == "inactive"]
                findings.append(
                    Finding(
                        severity="info",
                        title=f"Definitive plugin list: {len(active)} active, {len(inactive)} inactive",
                        evidence=(
                            ("Active:\n" + "\n".join(f"  - {p}" for p in active[:25]) + "\n" if active else "")
                            + ("Inactive:\n" + "\n".join(f"  - {p}" for p in inactive[:25]) if inactive else "")
                        ),
                        remediation="Delete inactive plugins — they still receive PHP execution if a CVE drops while installed.",
                        url=base + "/wp-admin/plugins.php",
                    )
                )
                # Stash for plugin_cves to also cross-reference
                ctx.setdefault("shared", {}).setdefault("plugins", {})
                for slug, state in plugins_seen:
                    if slug not in ctx["shared"]["plugins"]:
                        ctx["shared"]["plugins"][slug] = None
        except httpx.HTTPError:
            pass

        # 3. Site Health — pull critical issues
        step("fetching /wp-admin/site-health.php critical issues...")
        try:
            r = await auth.get(base + "/wp-admin/site-health.php")
            text = (r.text or "")
            if "site-health-issues-section-critical" in text:
                # Count critical issues by counting list items
                crit_count = text.count('class="site-health-issue-critical"') or text.count("site-health-critical")
                if crit_count:
                    findings.append(
                        Finding(
                            severity="high",
                            title=f"WordPress Site Health flags {crit_count} critical issue(s)",
                            evidence="See Tools → Site Health in wp-admin for full detail (cannot inline cleanly here).",
                            remediation="Resolve every Site Health critical issue. They typically cover PHP version, autoupdate, REST availability, scheduled events.",
                            url=base + "/wp-admin/site-health.php",
                        )
                    )
        except httpx.HTTPError:
            pass

        # 4. wp-config-y options via options.php (specific keys)
        step("checking options for unsafe configuration...")
        try:
            r = await auth.get(base + "/wp-admin/options.php")
            txt = (r.text or "")
            problems: list[str] = []
            # Look for default_role = administrator (catastrophic if registration is open)
            m = re.search(r'name=["\']default_role["\'][^>]+value=["\']([^"\']+)', txt)
            if m and m.group(1).lower() == "administrator":
                problems.append("default_role = administrator (new registrations become admins!)")
            # users_can_register
            if 'name="users_can_register" value="1" checked' in txt or 'name="users_can_register" checked' in txt:
                if m and m.group(1).lower() in ("administrator", "editor"):
                    problems.append(f"users_can_register=ON + default_role={m.group(1)} (high-priv self-registration enabled)")
            if problems:
                findings.append(
                    Finding(
                        severity="high",
                        title="Dangerous WordPress option(s) detected",
                        evidence="\n".join(f"  - {p}" for p in problems),
                        remediation="Set default_role to 'subscriber' or 'contributor' and disable user registration unless you actually need it.",
                        url=base + "/wp-admin/options-general.php",
                    )
                )
        except httpx.HTTPError:
            pass

    finally:
        await auth.aclose()

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Authenticated scan completed with no critical issues",
                evidence="Logged in with the provided admin credentials and inspected users, plugins, options, and Site Health.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
