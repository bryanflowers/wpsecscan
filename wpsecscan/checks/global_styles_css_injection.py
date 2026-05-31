"""F10 (v2.8.1) — FSE global-styles CSS injection probe.

Full Site Editing themes (WP 5.9+) accept user-supplied CSS via
`/wp-json/wp/v2/global-styles/<id>`. Update permission is normally
gated on `edit_theme_options`, but several theme + plugin combos
expose write access more broadly. We probe the read endpoint and
flag if the JSON contains user-defined CSS that could be tampered
with via an under-protected UPDATE endpoint.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F10: probing FSE global-styles endpoint")
    r = await client.get("/wp-json/wp/v2/global-styles?per_page=1")
    if r is None or r.status_code != 200:
        return []
    return [Finding(severity="low",
                     title="F10: FSE global-styles endpoint is publicly readable",
                     evidence=(
                         "GET /wp-json/wp/v2/global-styles returned 200. "
                         "If write permission is similarly relaxed, an attacker "
                         "could inject arbitrary CSS into every page (phishing-"
                         "overlay, login-form spoofing, CSP-bypass via "
                         "background-url exfil)."),
                     remediation=(
                         "Verify only `edit_theme_options` users can PATCH "
                         "/wp-json/wp/v2/global-styles/<id>. Audit FSE-theme "
                         "code for any `register_rest_route` callbacks that "
                         "lower the bar."),
                     url=ctx["target"])]
