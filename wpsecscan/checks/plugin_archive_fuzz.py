"""#6 (from wpscan --enumerate dbe) — dot-extension archive fuzz.

For every detected plugin slug, probes `/wp-content/plugins/<slug>.<ext>`
across common archive formats. A developer who zipped the plugin folder
for backup and uploaded it to the web root is one of the most common
ways production sites accidentally leak full plugin source.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


ARCHIVE_EXTS = ("zip", "tar", "tar.gz", "tgz", "rar", "7z", "sql.gz",
                "backup", "bak", "old")
MAX_SLUGS = 12  # cap to avoid request explosion on sites with 60+ plugins


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    shared = ctx.get("shared") or {}
    plugins = shared.get("plugins") or []
    slugs = [p.get("slug") for p in plugins if isinstance(p, dict) and p.get("slug")]
    slugs = slugs[:MAX_SLUGS]
    if not slugs:
        findings.append(Finding(
            severity="info",
            title="Plugin archive fuzz — no plugins detected",
            evidence="The `plugins` check didn't enumerate any slugs to fuzz against.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    hits: list[tuple[str, int, int]] = []  # (path, status, size)
    for slug in slugs:
        for ext in ARCHIVE_EXTS:
            path = f"/wp-content/plugins/{slug}.{ext}"
            step(f"archive fuzz {path}...")
            r = await client.head(path)
            if r is None:
                continue
            # 200 OK with non-trivial content-length = real archive
            if 200 <= r.status_code < 300:
                size = int(r.headers.get("content-length", 0) or 0)
                if size > 100:  # skip tiny stubs / decoy files
                    hits.append((path, r.status_code, size))

    if not hits:
        findings.append(Finding(
            severity="info",
            title=f"Plugin archive fuzz — no exposed backups ({len(slugs)} slugs × {len(ARCHIVE_EXTS)} extensions probed)",
            evidence="None of the slug.{zip,tar,gz,rar,7z,sql.gz,bak,old} variants returned a non-trivial body.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    findings.append(Finding(
        severity="critical",
        title=f"Plugin source archives exposed — {len(hits)} backup(s) reachable",
        evidence="\n".join(f"  - {p}  HTTP {s}, {sz} bytes" for p, s, sz in hits[:10])
        + ("\n  ... (+more)" if len(hits) > 10 else "")
        + ("\n\nDownloading a plugin .zip leaks the FULL source (including any hard-coded "
           "API keys, DB credentials, license tokens) and gives an attacker offline "
           "vulnerability research time."),
        remediation=(
            "Delete the archive files from the web root. Then prevent recurrence:\n"
            "  - Nginx: `location ~ \\.(zip|tar|gz|tgz|rar|7z|bak|old|backup)$ { deny all; }`\n"
            "  - Move backup workflow OUT of the web root (use `wp-cli db export ../backups/` "
            "with `..` to escape the doc root, or `rclone` to S3)"
        ),
        url=ctx["target"],
    ))
    return findings
