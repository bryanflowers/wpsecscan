"""B36-B47 (v2.6.0) — consumers of the companion plugin v1.3 endpoints.

Like `companion_advanced`, each consumer no-ops when --companion-token
isn't set so the scan doesn't add noise.

  B36 /users-with-app-passwords  — stale AP / many-AP / no-last-used flags
  B37 /recent-uploads            — recent PHP/JS in uploads = high (web-shell)
  B39 /wp-cron-event-history     — event count = derived (no logger active)
  B42 /admin-notice-content      — surface as info; manual review for ads
  B47 /site-health-tests         — flag each critical-status WP test
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


async def _hit(base: str, path: str, token: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(
                base.rstrip("/") + path,
                headers={"X-WPSecScan-Token": token,
                          "User-Agent": "WPSecScan/companion-v13"},
            )
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return None
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    return None


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00").split("+", 1)[0])
        return max(0, (datetime.now() - dt).days)
    except (ValueError, AttributeError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    token = ctx.get("companion_token")
    if not token:
        return findings  # silent no-op; companion_advanced already advised

    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"

    # B36 — users-with-app-passwords
    step("companion v1.3: users-with-app-passwords")
    aps = await _hit(base, "/wp-json/wpsecscan/v1/users-with-app-passwords", token)
    if aps and aps.get("supported"):
        for u in aps.get("users", []):
            for ap in u.get("app_passwords", []):
                age = _days_since(ap.get("created"))
                last = _days_since(ap.get("last_used"))
                if age is not None and age > 180:
                    findings.append(Finding(
                        severity="medium",
                        title=f"App Password stale (>180d): {u.get('user_login')} / {ap.get('name','?')}",
                        evidence=(
                            f"Created: {ap.get('created')} ({age}d ago)\n"
                            f"Last used: {ap.get('last_used') or 'never'}"
                            + (f" ({last}d ago)" if last is not None else "")
                            + f"\nLast IP: {ap.get('last_ip') or '-'}"
                        ),
                        remediation="Revoke or rotate via /wp-admin/profile.php → Application Passwords.",
                        url=client.url("/wp-admin/profile.php"),
                        extra={"user": u.get("user_login"), "ap_uuid": ap.get("uuid")},
                    ))

    # B37 — recent-uploads
    step("companion v1.3: recent-uploads")
    ups = await _hit(base, "/wp-json/wpsecscan/v1/recent-uploads?limit=200", token)
    if ups:
        php_js: list[dict] = []
        for f in ups.get("uploads", []):
            if (f.get("ext") or "").lower() in ("php", "phtml", "php5", "phar", "js"):
                php_js.append(f)
        if php_js:
            findings.append(Finding(
                severity="high",
                title=f"PHP/JS files in uploads/ (web-shell indicator): {len(php_js)}",
                evidence=(
                    "Recent PHP/JS uploads detected:\n  "
                    + "\n  ".join(f"[{f['ext']}] {f['path']} ({f['mtime']}, {f['size']}B)"
                                    for f in php_js[:10])
                    + ("\n  ..." if len(php_js) > 10 else "")
                ),
                remediation=(
                    "1. Audit each file: PHP in uploads/ is almost always a web-shell.\n"
                    "2. Block .php execution under uploads/ via web-server config\n"
                    "   (Apache: `<FilesMatch \\.ph(p[0-9]?|tml)$> Require all denied`;\n"
                    "   nginx: `location ~ ^/wp-content/uploads/.*\\.ph(p[0-9]?|tml)$ { deny all; }`).\n"
                    "3. Rotate all admin passwords + audit recent admin activity."
                ),
                url=client.url("/wp-content/uploads/"),
                extra={"files": [f["path"] for f in php_js[:20]]},
            ))

    # B39 — wp-cron-event-history (advisory: source = derived means no logger)
    step("companion v1.3: wp-cron-event-history")
    cron = await _hit(base, "/wp-json/wpsecscan/v1/wp-cron-event-history", token)
    if cron and cron.get("source") == "derived":
        findings.append(Finding(
            severity="info",
            title="WP-cron event history derived (no transient logger active)",
            evidence=(
                f"Companion returned {cron.get('count', 0)} events derived from "
                "_get_cron_array(). For better drift detection, enable the "
                "wpsecscan_companion_cron_history filter so the plugin logs "
                "actual elapsed-time per run."
            ),
            remediation=(
                "Add to your theme's functions.php:\n"
                "  add_action('init', function () {\n"
                "      add_filter('wpsecscan_companion_cron_history', '__return_true');\n"
                "  });\n"
                "Then re-scan to populate the history."
            ),
            url=client.url("/"),
            extra={"event_count": cron.get("count", 0)},
        ))

    # B42 — admin-notice-content (info)
    step("companion v1.3: admin-notice-content")
    notices = await _hit(base, "/wp-json/wpsecscan/v1/admin-notice-content", token)
    if notices and notices.get("count", 0) > 20:
        findings.append(Finding(
            severity="low",
            title=f"Many admin-notice-related wp_options ({notices['count']}) — review for adware",
            evidence=(
                f"{notices['count']} wp_options rows match admin_notice/dismissed.\n"
                "Some compromised plugins post admin notices with adware links. "
                "Review the first few entries:\n  "
                + "\n  ".join(n["name"] for n in notices.get("notices", [])[:8])
            ),
            remediation=(
                "Audit wp_options rows whose option_name contains 'admin_notice'\n"
                "or 'dismissed'. Each should belong to a known-installed plugin;\n"
                "orphans suggest a deactivated-but-not-cleaned plugin (or worse,\n"
                "a payload from a removed compromise)."
            ),
            url=client.url("/wp-admin/options.php"),
            extra={"notice_count": notices["count"]},
        ))

    # B47 — site-health-tests
    step("companion v1.3: site-health-tests")
    sh = await _hit(base, "/wp-json/wpsecscan/v1/site-health-tests", token)
    if sh and sh.get("supported"):
        for t in sh.get("tests", []):
            status = (t.get("status") or "").lower()
            if status == "critical":
                findings.append(Finding(
                    severity="high",
                    title=f"WordPress Site Health CRITICAL: {t.get('label') or t.get('name')}",
                    evidence=(
                        f"Test name: {t.get('name')}\n"
                        f"Label: {t.get('label') or '-'}\n"
                        f"Badge: {t.get('badge') or '-'}"
                    ),
                    remediation=(
                        "Open /wp-admin/site-health.php for the full Site Health\n"
                        "explanation + recommended fix. Critical-status tests are\n"
                        "the WP core team's curated 'must-fix' set."
                    ),
                    url=client.url("/wp-admin/site-health.php"),
                    extra={"site_health_test": t.get("name")},
                ))
            elif status == "recommended":
                findings.append(Finding(
                    severity="low",
                    title=f"WordPress Site Health recommended: {t.get('label') or t.get('name')}",
                    evidence=f"Test: {t.get('name')}, badge: {t.get('badge') or '-'}",
                    remediation="Open /wp-admin/site-health.php for context.",
                    url=client.url("/wp-admin/site-health.php"),
                    extra={"site_health_test": t.get("name")},
                ))

    return findings
