"""Per-year /wp-content/uploads/YYYY/ directory-listing probe.

The existing `directory_listing` check probes the uploads root. But many
shared-hosting `.htaccess` configurations disable autoindex at the
parent dir while leaving each year-subdirectory exposed (the `Options
-Indexes` directive applies per-scope and isn't propagated to children
on some Apache configs). We probe the last three calendar years
explicitly to catch those edge cases.
"""
from __future__ import annotations
from datetime import datetime, timezone
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    this_year = datetime.now(timezone.utc).year
    listings: list[tuple[str, int]] = []
    for y in (this_year, this_year - 1, this_year - 2):
        path = f"/wp-content/uploads/{y}/"
        step(f"probing {path} for directory listing...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        body = r.text.lower()
        if ("<title>index of" in body) or ("<h1>index of" in body):
            listings.append((path, len(r.text)))
    if not listings:
        return findings
    lines = "\n".join(f"  {p}  ({n} bytes)" for p, n in listings)
    findings.append(Finding(
        severity="high",
        title=f"Per-year uploads directory listing enabled ({len(listings)} year(s))",
        evidence=(
            f"Year-subdirectory autoindex is returning a real Apache/Nginx "
            f"directory listing:\n{lines}\n\n"
            "Sometimes a parent rule (Options -Indexes) doesn't propagate to "
            "year subdirectories, especially on cPanel shared hosting. Visitors "
            "can now enumerate every uploaded file by year."
        ),
        remediation=(
            "Add `Options -Indexes` to the deepest level needed, or drop an "
            "empty `index.html` into each year directory as belt-and-braces. "
            "Nginx: ensure `autoindex off` (the default) and verify no location "
            "block re-enables it for /wp-content/uploads/."
        ),
        url=client.url("/wp-content/uploads/"),
        extra={"affected_paths": [p for p, _ in listings]},
    ))
    return findings
