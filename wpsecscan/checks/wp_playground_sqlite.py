"""A4 (v2.6.0) — WP Playground / SQLite-Database-Integration detection.

The official "wp-now" / "WordPress Playground" runtime ships a SQLite
database driver instead of MySQL. The same SQLite-Database-Integration
plugin is used in production by anyone running WordPress on a host
without MySQL.

The plugin has its own CVE family — particularly around the SQL
translation layer that converts MySQL queries to SQLite. Some
historical bugs:

  • Translation-layer query injection (CVE-2024-3xxx).
  • Database file (`wp-content/database/.ht.sqlite`) reachable via the
    web when .htaccess isn't honoured (nginx-served installs).
  • Backup file (`.ht.sqlite.bak`) sometimes left readable.

This check fingerprints the plugin via the rendered HTML + probes the
canonical database-file paths.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_DB_PATHS = (
    "/wp-content/database/.ht.sqlite",
    "/wp-content/database/.ht.sqlite.bak",
    "/wp-content/database/wp.sqlite",
    "/wp-content/database/.ht.sqlite-journal",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("SQLite-DB-Integration fingerprint")
    home = await client.get("/")
    body = (home.text or "") if home else ""

    sqlite_detected = (
        "sqlite-database-integration" in body
        or "wp-now" in body.lower()
        or "playground.wordpress.net" in body
    )

    for path in _DB_PATHS:
        step(f"SQLite DB-file probe: {path}")
        r = await client.get(path)
        if r is None:
            continue
        # SQLite files start with "SQLite format 3" bytes.
        if r.status_code == 200 and r.content and r.content.startswith(b"SQLite format 3"):
            findings.append(Finding(
                severity="critical",
                title=f"WordPress SQLite database file is web-reachable: {path}",
                evidence=(
                    f"GET {path} → HTTP 200 ({len(r.content)} bytes).\n"
                    f"First 32 bytes (hex): {r.content[:32].hex()}\n"
                    "Magic bytes confirm this is the live SQLite file. Anyone\n"
                    "on the internet can download the entire WordPress database\n"
                    "(users, options, posts, all metadata)."
                ),
                remediation=(
                    "1. IMMEDIATE: block /wp-content/database/ at the WAF.\n"
                    "2. Move the database file outside the web root (set DB_DIR\n"
                    "   in wp-config.php to a path above ABSPATH).\n"
                    "3. On nginx, add `location /wp-content/database/ { deny all; }`.\n"
                    "4. Rotate all user passwords + any API keys stored in wp_options.\n"
                    "5. Audit for unauthorised access via web-server logs.\n"
                    "6. After remediation, change wp-config.php SECRET_AUTH_KEY etc.\n"
                    "   so any session tokens captured during the leak window become invalid."
                ),
                url=client.url(path),
                extra={"file_size": len(r.content),
                        "category": "database-exposure"},
            ))
            return findings  # one critical is enough

        if r.status_code == 200 and len(r.content or b"") < 5000:
            # Some hosts return the file but with an obfuscated header.
            findings.append(Finding(
                severity="high",
                title=f"Possible SQLite database file reachable: {path}",
                evidence=(
                    f"GET {path} → HTTP 200 ({len(r.content)} bytes).\n"
                    "Doesn't match the SQLite magic header, but the path is "
                    "reachable and is the canonical SQLite-DB-Integration location."
                ),
                remediation=(
                    "Block /wp-content/database/ at the WAF and move the DB file\n"
                    "outside the web root (see DB_DIR in wp-config.php)."
                ),
                url=client.url(path),
                extra={"category": "database-exposure"},
            ))

    if sqlite_detected and not findings:
        findings.append(Finding(
            severity="info",
            title="WordPress SQLite-Database-Integration detected (DB file not web-reachable)",
            evidence=(
                "Homepage HTML or response headers indicate this install uses\n"
                "the official SQLite-Database-Integration plugin (or wp-now /\n"
                "WordPress Playground). The /wp-content/database/ path is NOT\n"
                "reachable from the web, which is the expected hardened state."
            ),
            remediation=(
                "Verify wp-config.php has DB_DIR set to a path above ABSPATH,\n"
                "and that .htaccess or nginx config denies /wp-content/database/."
            ),
            url=str(client.base_url),
            extra={"category": "database-stack"},
        ))
    return findings
