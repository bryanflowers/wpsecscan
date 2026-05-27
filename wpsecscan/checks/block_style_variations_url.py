"""O145 (v2.6.0) — Block-Style-Variations URL-prop SSRF.

Gutenberg 16+ block-style variations can carry URL-shaped properties
(e.g. a background-image URL) that the theme renders server-side via
PHP `file_get_contents` or similar. Mis-validated themes have allowed
the URL to point at internal hosts.

Passive: read the rendered HTML for `data-wp-style-*` and inline-style
`url(http://...)` references; flag when any URL points to an internal-
looking host (localhost, 127.0.0.1, 169.254.169.254, RFC1918 ranges).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_URL_RE = re.compile(r'url\(\s*[\'"]?(https?://[^\)\'"\s]+)', re.IGNORECASE)

_PRIVATE_HOSTS = (
    "127.", "localhost", "169.254.169.254", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.", "::1", "fc00:", "fe80:",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Block-style URL probe: GET /")
    r = await client.get("/")
    if r is None or not r.text:
        return findings

    internal: list[str] = []
    for m in _URL_RE.finditer(r.text):
        url = m.group(1)
        host_part = url.split("//", 1)[1].split("/", 1)[0]
        if any(host_part.startswith(p) for p in _PRIVATE_HOSTS):
            internal.append(url[:200])

    if internal:
        findings.append(Finding(
            severity="medium",
            title=f"Block-style URL points to internal host(s): {len(internal)}",
            evidence=(
                "Internal-host URLs found in rendered CSS/HTML:\n  "
                + "\n  ".join(internal[:10])
            ),
            remediation=(
                "1. Find the block style or block-style variation that emits\n"
                "   these URLs (Customizer → Additional CSS, or theme.json).\n"
                "2. Replace with public URLs OR remove if leftover from staging.\n"
                "3. Internal URLs in CSS can be leveraged for cache-poisoning\n"
                "   or SSRF (when a plugin processes the resolved URL server-side)."
            ),
            url=client.url("/"),
            extra={"internal_urls": internal[:10]},
        ))
    return findings
