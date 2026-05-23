"""H7 Backup-file long-tail fuzzer.

Existing `exposed_files` and `backup_exposure` checks cover the common cases
(`wp-config.php.bak`, `.git/config`, etc.). This fuzzer extends the tail with
~30 less-common variants that often slip through.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Variants of wp-config.php that backup tools / editors / IDEs leave behind
WP_CONFIG_VARIANTS = (
    "wp-config.php~",          # vim/emacs backup
    "wp-config.php.swp",       # vim swap
    ".wp-config.php.swp",      # vim swap with leading dot
    "wp-config.php.tmp",       # editor temp
    "wp-config.php.orig",      # patch backup
    "wp-config.php.save",      # nano save
    "wp-config.php.txt",       # accidental text save
    "wp-config.php-",          # bare backup char
    "wp-config-backup.php",    # human rename
    "wp-config.php.bak.old",   # double-backup
    "wp-config.php.bak2",      # numbered
    "wp-config.php.copy",      # rename
    "wp-config.old",           # short
    "wp-config.bak",           # short
    "wp-config-old.php",       # human rename
    "wp_config.php",           # underscore variant
    "wp-config.php.disabled",  # explicit disable
    "wp-config.dev.php",       # env variant
    "wp-config.staging.php",   # env variant
    "wp-config.production.php",# env variant
    "wp-config-sample.php.bak",# sample backup
    ".wp-config.php",          # leading dot
)

# IDE / dev-tool config that often gets committed by mistake
IDE_CONFIG = (
    ".vscode/settings.json",
    ".vscode/launch.json",
    ".idea/workspace.xml",
    ".idea/deployment.xml",
    ".idea/dataSources.xml",  # contains DB creds
    "nbproject/project.properties",
    ".project",
    ".classpath",
)

# Editor-leftover files (less common but high-impact when found)
EDITOR_LEFTOVERS = (
    ".DS_Store",        # often committed accidentally
    "Thumbs.db",        # Windows
    "._wp-config.php",  # macOS resource fork
    "desktop.ini",      # Windows folder config
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("backup-file fuzzer: wp-config variants...")
    hits: list[tuple[str, int, int]] = []  # (path, status, len)

    for path in WP_CONFIG_VARIANTS + IDE_CONFIG + EDITOR_LEFTOVERS:
        r = await client.get("/" + path)
        if r is None:
            continue
        # Treat 2xx with non-trivial body as a hit. Some servers also return 200 with WP
        # 404 page; those have content-type text/html — filter to text/plain or content-len > 200
        if 200 <= r.status_code < 300 and len(r.content or b"") > 50:
            # WP standard 404 page is usually >2000 bytes — if body looks like the 404
            # template (contains "Page not found"), skip
            body = (r.text or "")[:500].lower()
            if "page not found" in body or "404" in body and len(r.content or b"") > 5000:
                continue
            hits.append((path, r.status_code, len(r.content or b"")))

    if hits:
        sev = "critical" if any("wp-config" in p for p, _s, _l in hits) else "high"
        findings.append(Finding(
            severity=sev,
            title=f"Backup-file fuzzer — {len(hits)} sensitive file(s) reachable",
            evidence="\n".join(f"  - /{p} -> HTTP {s} ({l} bytes)" for p, s, l in hits[:20]),
            remediation=(
                "Block these patterns in your web server config. Nginx example:\n"
                "  location ~ \\.(bak|swp|tmp|orig|save|old|copy|disabled|dev|staging|production)$ { deny all; }\n"
                "  location ~ /\\.(git|vscode|idea|DS_Store|svn) { deny all; }\n"
                "  location = /wp-config.php { deny all; }\n\n"
                "Apache equivalent in .htaccess:\n"
                "  <FilesMatch \"\\.(bak|swp|tmp|orig|save|old|copy)$\">\n"
                "    Require all denied\n"
                "  </FilesMatch>"
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"Backup-file fuzzer — clean ({len(WP_CONFIG_VARIANTS + IDE_CONFIG + EDITOR_LEFTOVERS)} variants probed)",
            evidence="No backup / IDE / editor files reachable.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
