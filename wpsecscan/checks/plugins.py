from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

PLUGIN_PATH_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9][a-z0-9_\-]*)/", re.IGNORECASE
)
PLUGIN_VERSION_RE = re.compile(r"\?ver=([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE)
README_STABLE_RE = re.compile(r"Stable tag:\s*([0-9][0-9A-Za-z.\-_]*)", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    # Probe several pages, not just home — different plugins load on different surfaces.
    PAGES = ("/", "/?p=1", "/wp-login.php", "/feed/", "/sample-page/", "/?page_id=2")
    slugs: dict[str, str | None] = {}
    pages_seen = 0
    for path in PAGES:
        step(f"scanning {path} for plugin asset URLs...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        pages_seen += 1
        body = r.text
        for m in PLUGIN_PATH_RE.finditer(body):
            slug = m.group(1).lower()
            tail = body[m.end(): m.end() + 200]
            v = PLUGIN_VERSION_RE.search(tail)
            ver = v.group(1) if v else None
            existing = slugs.get(slug)
            # Prefer pages that gave us a version
            if slug not in slugs or (existing is None and ver):
                slugs[slug] = ver

    if pages_seen == 0:
        return findings

    if not slugs:
        findings.append(
            Finding(
                severity="info",
                title="No plugins discovered via HTML enumeration",
                evidence=f"Probed {pages_seen} page(s); no /wp-content/plugins/<slug>/ references found.",
                remediation="Either plugins are masked (good) or the site is light on plugins. No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    ctx["shared"]["plugins"] = slugs

    exposed_readmes: list[tuple[str, str]] = []
    for slug, _ in list(slugs.items())[:30]:  # cap to first 30 to be polite
        step(f"fetching readme.txt for {slug}...")
        r = await client.get(f"/wp-content/plugins/{slug}/readme.txt")
        if r is not None and r.status_code == 200 and "Stable tag" in (r.text or ""):
            sm = README_STABLE_RE.search(r.text)
            ver = sm.group(1) if sm else "unknown"
            exposed_readmes.append((slug, ver))
            if slugs[slug] is None:
                slugs[slug] = ver

    plugin_lines = "\n".join(
        f"  - {slug}  (version: {ver or 'unknown'})" for slug, ver in slugs.items()
    )
    findings.append(
        Finding(
            severity="info",
            title=f"{len(slugs)} plugin(s) discovered via HTML asset paths",
            evidence=f"Plugin slugs found across {pages_seen} probed page(s):\n{plugin_lines}",
            remediation="Plugin slugs being discoverable is normal but useful to attackers. Keep all listed plugins updated. Consider a WAF that strips ?ver= asset query strings.",
            url=ctx["target"],
        )
    )

    if exposed_readmes:
        readme_lines = "\n".join(f"  - {s}: version {v}" for s, v in exposed_readmes)
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(exposed_readmes)} plugin(s) expose readme.txt with version",
                evidence=f"readme.txt accessible for:\n{readme_lines}",
                remediation="Block /wp-content/plugins/*/readme.txt at the server level. Public readme files leak exact plugin versions, making CVE matching trivial.",
                url=client.url("/wp-content/plugins/"),
            )
        )

    # WPScan API CVE cross-reference (optional, opt-in via --wpscan-token).
    # Has migrated to plugin_cves check; keeping the inline call removed for clarity.
    return findings
