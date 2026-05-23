"""Plugin / configuration recommendation engine.

Given a ScanReport, returns a list of *actionable* recommendations grouped by
the underlying plugin/config you should install or change. Turns 30+ findings
into a 5-bullet "buy-list".

Static mapping; lives here so reporters + GUI can both consume it.
"""
from __future__ import annotations

from .models import ScanReport

# (check_id, recommendation_key, plugin_name, install_command, why)
RECOMMENDATIONS: dict[str, dict] = {
    "login_throttle": {
        "key": "rate-limit-login",
        "title": "Install a login rate-limiter",
        "plugin": "Limit Login Attempts Reloaded",
        "wp_cli": "wp plugin install limit-login-attempts-reloaded --activate",
        "why": "Blocks credential-stuffing at the HTTP layer. Free, no config.",
    },
    "login_throttle_deep": {
        "key": "rate-limit-login",
        "title": "Install a login rate-limiter",
        "plugin": "Limit Login Attempts Reloaded",
        "wp_cli": "wp plugin install limit-login-attempts-reloaded --activate",
        "why": "Blocks credential-stuffing at the HTTP layer. Free, no config.",
    },
    "tls_headers": {
        "key": "security-headers",
        "title": "Install a security-headers plugin",
        "plugin": "HTTP Headers Security",
        "wp_cli": "wp plugin install http-headers --activate",
        "why": "Adds HSTS, CSP, X-Frame-Options, Referrer-Policy with a UI.",
    },
    "csp": {
        "key": "security-headers",
        "title": "Install a security-headers plugin",
        "plugin": "HTTP Headers Security",
        "wp_cli": "wp plugin install http-headers --activate",
        "why": "Configurable CSP with reporting endpoint.",
    },
    "cookies": {
        "key": "security-headers",
        "title": "Install a security-headers plugin",
        "plugin": "HTTP Headers Security",
        "wp_cli": "wp plugin install http-headers --activate",
        "why": "Configures Secure / HttpOnly / SameSite for session cookies.",
    },
    "users": {
        "key": "hide-author-enum",
        "title": "Block author enumeration",
        "plugin": "Stop User Enumeration",
        "wp_cli": "wp plugin install stop-user-enumeration --activate",
        "why": "Returns 404 on /?author=N and /wp-json/wp/v2/users to non-admins.",
    },
    "core_tampering": {
        "key": "malware-scanner",
        "title": "Install a malware scanner",
        "plugin": "Wordfence",
        "wp_cli": "wp plugin install wordfence --activate",
        "why": "Compares your wp-includes/* files against the official release checksums.",
    },
    "backup_exposure": {
        "key": "backup-protect",
        "title": "Move backups out of /wp-content",
        "plugin": "UpdraftPlus (with remote storage)",
        "wp_cli": "wp plugin install updraftplus --activate",
        "why": "Configure to upload to S3/Drive/Dropbox so backups never sit in the docroot.",
    },
    "default_creds": {
        "key": "2fa",
        "title": "Enforce 2FA on admin accounts",
        "plugin": "Two-Factor",
        "wp_cli": "wp plugin install two-factor --activate",
        "why": "Even if a default credential leaks, 2FA blocks the login.",
    },
    "exposed_files": {
        "key": "block-paths",
        "title": "Block sensitive paths at the web server",
        "plugin": "Solid Security / iThemes Security",
        "wp_cli": "wp plugin install better-wp-security --activate",
        "why": "One-click rules to block .env, .git, wp-config.php.bak, debug.log.",
    },
    "xmlrpc_deep": {
        "key": "disable-xmlrpc",
        "title": "Disable XML-RPC",
        "plugin": "Disable XML-RPC",
        "wp_cli": "wp plugin install disable-xml-rpc --activate",
        "why": "Removes the system.multicall brute-force amplifier in one click.",
    },
    "dns_security": {
        "key": "email-auth",
        "title": "Configure SPF / DMARC at your DNS",
        "plugin": "(DNS records, no plugin)",
        "wp_cli": "# DNS-level — see https://easydmarc.com/tools/dmarc-record-generator",
        "why": "Stops spoofed emails from your domain reaching inboxes.",
    },
    "cookie_consent": {
        "key": "consent-banner",
        "title": "Install a GDPR consent banner",
        "plugin": "Complianz (or CookieYes)",
        "wp_cli": "wp plugin install complianz-gdpr --activate",
        "why": "Blocks analytics/marketing scripts until consent. Required in EU.",
    },
    "wpgraphql": {
        "key": "graphql-hardening",
        "title": "Disable GraphQL introspection in production",
        "plugin": "(WPGraphQL plugin settings — no extra plugin)",
        "wp_cli": "# add_filter('graphql_introspection_enabled', '__return_false');",
        "why": "Stops attackers from auto-mapping your schema.",
    },
    "secret_leak": {
        "key": "secret-scanner",
        "title": "Pre-commit secret scanning",
        "plugin": "(gitleaks / TruffleHog at the dev pipeline)",
        "wp_cli": "# Add to CI: trufflehog filesystem .",
        "why": "Catches AKIA*, sk_live_*, ghp_* before they ship to production.",
    },
    "directory_listing": {
        "key": "disable-dir-listing",
        "title": "Disable directory listing at the web server",
        "plugin": "(server config: Apache `Options -Indexes`, Nginx `autoindex off;`)",
        "wp_cli": "# Edit nginx.conf / .htaccess directly",
        "why": "Stops `Index of /wp-content/uploads/` exposing every upload.",
    },
    "debug_leaks": {
        "key": "disable-wp-debug",
        "title": "Disable WP_DEBUG in production",
        "plugin": "(edit wp-config.php)",
        "wp_cli": "# define('WP_DEBUG', false); define('WP_DEBUG_DISPLAY', false);",
        "why": "Hides PHP errors, query traces, and the install path.",
    },
}


def recommendations_for(report: ScanReport) -> list[dict]:
    """Group non-info findings into the smallest set of actionable recommendations.

    Returns a list of dicts (one per unique recommendation key):
      {key, title, plugin, wp_cli, why, triggered_by: [check_id, ...]}
    """
    by_key: dict[str, dict] = {}
    for r in report.results:
        if r.error:
            continue
        # Only recommend things if there's at least one actionable finding
        non_info = [f for f in r.findings if f.severity != "info"]
        if not non_info:
            continue
        rec = RECOMMENDATIONS.get(r.check_id)
        if not rec:
            continue
        bucket = by_key.setdefault(rec["key"], {
            "key": rec["key"],
            "title": rec["title"],
            "plugin": rec["plugin"],
            "wp_cli": rec["wp_cli"],
            "why": rec["why"],
            "triggered_by": [],
        })
        bucket["triggered_by"].append(r.check_id)
    return list(by_key.values())
