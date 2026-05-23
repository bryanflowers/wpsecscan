from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

THEME_PATH_RE = re.compile(
    r"/wp-content/themes/([a-z0-9][a-z0-9_\-]*)/", re.IGNORECASE
)
THEME_VERSION_HEADER_RE = re.compile(r"Version:\s*([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("scanning / for theme asset URLs...")
    home = await client.get("/")
    if home is None or home.status_code != 200 or not home.text:
        return findings

    slugs: dict[str, str | None] = {}
    for m in THEME_PATH_RE.finditer(home.text):
        slug = m.group(1).lower()
        if slug not in slugs:
            slugs[slug] = None

    if not slugs:
        return findings

    ctx["shared"]["themes"] = slugs

    for slug in list(slugs.keys())[:10]:
        step(f"fetching style.css for theme {slug}...")
        r = await client.get(f"/wp-content/themes/{slug}/style.css")
        if r is not None and r.status_code == 200 and "Theme Name" in (r.text or "")[:2000]:
            head = r.text[:2000]
            vm = THEME_VERSION_HEADER_RE.search(head)
            slugs[slug] = vm.group(1) if vm else None

    lines = "\n".join(f"  - {s}  (version: {v or 'unknown'})" for s, v in slugs.items())
    findings.append(
        Finding(
            severity="info",
            title=f"{len(slugs)} theme(s) discovered via HTML asset paths",
            evidence=f"Theme slugs found:\n{lines}",
            remediation="Keep all installed themes updated, including inactive ones. Delete unused themes — inactive themes still receive PHP execution if a CVE lands.",
            url=ctx["target"],
        )
    )

    return findings
