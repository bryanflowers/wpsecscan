"""Backup-plugin exposure check.

Backup plugins are a top WordPress info-leak source — they all write to
predictable paths under wp-content, and operators frequently forget to
add web-server level deny rules.

Severity logic:
  - .sql / .sqlite / .wpress / wp-config-in-backup = critical (immediate DB credential leak)
  - .zip / .tar.gz of the site = high (full site source + secrets)
  - log files / readme = low (info disclosure but not catastrophic)
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# (path, severity, label)
BACKUP_PATHS: tuple[tuple[str, str, str], ...] = (
    # UpdraftPlus
    ("/wp-content/updraft/",                             "high",     "UpdraftPlus backup directory"),
    ("/wp-content/updraft/index.html",                   "low",      "UpdraftPlus index"),
    ("/wp-content/updraft/log.log",                      "medium",   "UpdraftPlus log"),
    # BackWPup
    ("/wp-content/uploads/backwpup-logs/",               "medium",   "BackWPup log directory"),
    ("/wp-content/uploads/backwpup-backups/",            "high",     "BackWPup backup directory"),
    # Duplicator
    ("/wp-snapshots/",                                   "high",     "Duplicator snapshots"),
    ("/installer.php",                                   "critical", "Duplicator installer left behind"),
    ("/installer-backup.php",                            "critical", "Duplicator installer-backup left behind"),
    ("/wp-content/backups-dup-lite/",                    "high",     "Duplicator Lite backup directory"),
    ("/wp-content/backups-dup-pro/",                     "high",     "Duplicator Pro backup directory"),
    # BackupBuddy / Solid Backups
    ("/wp-content/uploads/backupbuddy_backups/",         "high",     "BackupBuddy backup directory"),
    ("/wp-content/uploads/backupbuddy_temp/",            "medium",   "BackupBuddy temp directory"),
    ("/importbuddy.php",                                 "critical", "BackupBuddy importbuddy.php left behind"),
    # All-in-One WP Migration
    ("/wp-content/ai1wm-backups/",                       "critical", "All-in-One WP Migration backup directory (often contains *.wpress with full DB)"),
    # WP Time Capsule
    ("/wp-content/uploads/wp-time-capsule/",             "high",     "WP Time Capsule backups"),
    # WPvivid
    ("/wp-content/wpvividbackups/",                      "high",     "WPvivid backup directory"),
    # XCloner
    ("/wp-content/uploads/xcloner-backups/",             "high",     "XCloner backup directory"),
    # Generic blind backup filenames at docroot
    ("/backup.zip",                                      "critical", "Generic backup.zip at docroot"),
    ("/site.zip",                                        "critical", "Generic site.zip at docroot"),
    ("/wordpress.zip",                                   "critical", "Generic wordpress.zip at docroot"),
    ("/database.sql",                                    "critical", "Database dump at docroot"),
    ("/wp-database.sql",                                 "critical", "WordPress database dump at docroot"),
    ("/wp.sql",                                          "critical", "WordPress database dump at docroot"),
    ("/dump.sql",                                        "critical", "Database dump at docroot"),
    ("/db.sql.gz",                                       "critical", "Compressed database dump at docroot"),
    ("/wp.tar.gz",                                       "high",     "WordPress tarball at docroot"),
)

# After hitting a directory, try to find evidence of actual backup files in the listing
LISTING_FILE_PATTERN = re.compile(r'href="([^"]+\.(?:sql|sqlite|zip|tar\.gz|tgz|wpress|gz|7z|bz2))"', re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    suspicious: list[dict] = []

    for path, sev, label in BACKUP_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        ct = r.headers.get("content-type", "")

        # Heuristic: HTML body with "Index of" or backup-file extensions in <a href=> = directory listing
        is_listing = (
            "<title>index of" in body.lower()
            or 'href="' in body.lower() and any(
                ext in body.lower() for ext in (".sql", ".zip", ".tar.gz", ".wpress", ".sqlite")
            )
        )
        # Heuristic: actual backup file (non-HTML response) downloaded
        is_blob = ct and ("application/" in ct or "octet-stream" in ct or "zip" in ct or "sql" in ct)

        # Recognize plain-text log files that mention the backup plugin
        body_markers = ("updraftplus", "backwpup", "backupbuddy", "ai1wm", "wpvivid", "duplicator", "snapshot")
        looks_logged = "text/plain" in ct and any(m in (body or "").lower() for m in body_markers)
        ext_match = path.endswith((".php", ".sql", ".zip", ".gz", ".sqlite", ".tar.gz", ".wpress", ".log", ".txt"))
        if not (is_listing or is_blob or ext_match or looks_logged):
            # 200 but doesn't look like a backup — skip (probably a soft 404)
            continue

        suspicious.append({
            "path": path,
            "label": label,
            "severity": sev,
            "status": r.status_code,
            "content_type": ct,
            "size": len(r.content or b""),
            "is_listing": is_listing,
            "is_blob": is_blob,
            "files_in_listing": LISTING_FILE_PATTERN.findall(body) if is_listing else [],
        })

    for s in suspicious:
        ev_lines = [
            f"GET {s['path']} -> HTTP {s['status']} ({s['content_type'] or 'unknown content-type'})",
            f"  Size: {s['size']} bytes",
            f"  Directory listing: {s['is_listing']}",
        ]
        if s["files_in_listing"]:
            ev_lines.append(f"  Files in listing (first 5): {', '.join(s['files_in_listing'][:5])}")
        if s["is_blob"]:
            ev_lines.append("  Response looks like an actual binary download.")

        findings.append(
            Finding(
                severity=s["severity"],
                title=f"Backup-plugin exposure: {s['label']}",
                evidence="\n".join(ev_lines) + (
                    "\n\nBackup files left in the web root are one of the highest-impact WP info leaks — "
                    "a SQL dump contains DB credentials and all user data; a site .zip contains every secret in wp-config.php."
                ),
                remediation=(
                    "1. **Right now**: delete the exposed files from the web root.\n"
                    "2. Block backup-plugin paths at the web server. Nginx example:\n"
                    "     location ~ ^/(wp-content/(updraft|backups-dup-lite|backups-dup-pro|ai1wm-backups|wpvividbackups|"
                    "uploads/backwpup-backups|uploads/backupbuddy_backups|uploads/wp-time-capsule|uploads/xcloner-backups))(/.*)?$ { deny all; }\n"
                    "3. Audit the backup-plugin config to write OUTSIDE the docroot (S3, off-site).\n"
                    "4. Rotate every DB and WP secret that may have been in an exposed dump."
                ),
                url=client.url(s["path"]),
                extra={"backup_plugin_path": s["path"], "size_bytes": s["size"]},
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No backup-plugin exposure detected",
                evidence=f"Probed {len(BACKUP_PATHS)} common backup-plugin paths; none returned anything that looked like an exposed backup.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
