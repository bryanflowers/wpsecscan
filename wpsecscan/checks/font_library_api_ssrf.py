"""O143 (v2.6.0) — Font Library API SSRF audit.

WP 6.5 added the Font Library at /wp-json/wp/v2/font-families. The
endpoint accepts font-collection JSON with a `src` URL; on install,
WordPress fetches the URL server-side via wp_remote_get. Bug history:

  • Pre-6.5.5 installs accepted any URL including file://, http://
    internal, ftp:// → classic SSRF.
  • The `permission_callback` requires `edit_theme_options`, but
    several plugins added a passthrough endpoint that lowers the bar.

Passive: probe the route, observe auth requirement. Surface info
when properly auth-gated, low when 200 (Font Library config readable
unauth).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PATHS = (
    "/wp-json/wp/v2/font-families",
    "/wp-json/wp/v2/font-collections",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PATHS:
        step(f"font-library probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code == 404:
            continue
        if r.status_code == 200:
            findings.append(Finding(
                severity="low",
                title=f"WP Font Library endpoint readable unauthenticated: {path}",
                evidence=(
                    f"GET {path} → HTTP 200.\n"
                    "Font Library reads are typically auth-gated to "
                    "edit_theme_options. An anonymous 200 suggests a custom "
                    "plugin / mu-plugin lowered the permission."
                ),
                remediation=(
                    "1. Confirm WordPress core >= 6.5.5 (SSRF patch).\n"
                    "2. Find which plugin overrides the rest_authentication\n"
                    "   filter / lowers the font-family endpoint permission.\n"
                    "3. Audit any custom font-source URL in the install — those\n"
                    "   are pre-validated server-fetched and must be HTTPS\n"
                    "   public URLs only (no file:// / http:// internal)."
                ),
                url=client.url(path),
                extra={"path": path, "status": r.status_code},
            ))
    return findings
