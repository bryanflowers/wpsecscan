"""A18 (v2.6.0) — PWA service-worker cache exposure.

PWA plugins (Super-Progressive-Web-Apps, Simple-PWA, PWA for WP)
register a service worker whose `precache` list is fetched on install.
When the precache list includes `/wp-admin/` paths or admin-only assets,
those URLs become cached for any visitor who installs the PWA — they
end up in the browser's offline cache.

Passive: GET `/sw.js` + `/service-worker.js` and scan the response for
admin URL prefixes.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_SW_PATHS = ("/sw.js", "/service-worker.js", "/pwa-sw.js",
              "/wp-content/cache/sw.js")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _SW_PATHS:
        step(f"PWA SW probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        body = r.text
        admin_urls = re.findall(r'["\'](/wp-admin/[^"\']{0,200})["\']', body)
        if admin_urls:
            findings.append(Finding(
                severity="high",
                title=f"PWA service worker precaches admin URLs: {path}",
                evidence=(
                    f"GET {path} returns a SW that precaches /wp-admin/ paths.\n"
                    f"Sample: {', '.join(sorted(set(admin_urls))[:8])}\n"
                    "When any visitor installs the PWA, their browser caches "
                    "these admin URLs — content visible to the install user "
                    "leaks into the offline cache."
                ),
                remediation=(
                    "1. Open the PWA plugin Settings and remove /wp-admin/ from "
                    "the precache list.\n"
                    "2. In the SW's `precacheAndRoute(...)` call, exclude any URL "
                    "matching /^\\/wp-admin\\//.\n"
                    "3. Tell users to clear site data once after the fix."
                ),
                url=client.url(path),
                extra={"admin_urls_sample": sorted(set(admin_urls))[:20]},
            ))
            break  # one SW is enough
    return findings
