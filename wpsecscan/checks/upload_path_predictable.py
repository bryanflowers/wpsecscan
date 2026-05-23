"""Predictable upload-path probe.

WordPress stores uploads at /wp-content/uploads/YYYY/MM/<file>. If directory
listing is off but the admin uploads files with predictable names (logo.png,
admin-screenshot.png, draft.pdf), an attacker can guess and access "private"
uploads that aren't linked from any page.

Probes ~20 common admin-uploaded filenames in the current month/year folder.
GET-only, low rate.
"""
from __future__ import annotations

from datetime import datetime

from ..http import Client
from ..models import Finding

COMMON_NAMES = (
    "admin.png", "logo.png", "screenshot.png", "screenshot.jpg",
    "image.png", "image.jpg", "test.png", "test.jpg", "test.pdf",
    "private.pdf", "draft.pdf", "internal.pdf", "notes.pdf",
    "backup.zip", "export.csv", "users.csv", "members.csv",
    "report.pdf", "invoice.pdf", "contract.pdf", "private.zip",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    now = datetime.utcnow()
    year, month = now.year, now.month
    # Probe current month and previous month
    months_to_probe = [(year, month)]
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    months_to_probe.append((prev_year, prev_month))

    hits: list[tuple[str, int]] = []  # (path, size_bytes)
    for y, m in months_to_probe:
        for name in COMMON_NAMES:
            path = f"/wp-content/uploads/{y}/{m:02d}/{name}"
            step(f"probing {path}...")
            r = await client.head(path)
            if r is None:
                continue
            if r.status_code == 200:
                try:
                    size = int(r.headers.get("content-length", "") or "0")
                except ValueError:
                    size = 0
                hits.append((path, size))

    if not hits:
        findings.append(
            Finding(
                severity="info",
                title="No predictable-name uploads found in current/previous month",
                evidence=f"Probed {len(COMMON_NAMES) * 2} common admin-uploaded filenames in /wp-content/uploads/.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    sample = "\n".join(f"  - {p}  ({sz} bytes)" for p, sz in hits[:10])
    findings.append(
        Finding(
            severity="medium",
            title=f"{len(hits)} predictable-name file(s) reachable in /wp-content/uploads/",
            evidence=(
                f"Found:\n{sample}\n\n"
                "These uploads aren't linked from the public site but are reachable by guessing "
                "the filename. Admin-uploaded 'private' files (drafts, internal docs, member exports) "
                "can leak this way even when directory listing is disabled."
            ),
            remediation=(
                "(1) Rename sensitive uploads to include a hash or random suffix.\n"
                "(2) For truly-private files, use a plugin that serves uploads through PHP with auth "
                "(e.g. WP-Members, Restrict File Access) instead of leaving them at the public uploads URL.\n"
                "(3) Or add `<Files \"*.pdf\">Require all denied</Files>` to the uploads .htaccess and "
                "serve restricted files via a signed-URL plugin."
            ),
            url=client.url("/wp-content/uploads/"),
        )
    )
    return findings
