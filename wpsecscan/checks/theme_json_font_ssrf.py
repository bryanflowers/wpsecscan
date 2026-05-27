"""A24 (v2.6.0) — theme.json font-source SSRF probe.

Gutenberg 6.2+ accepts a remote `fontFamilies.source` URL in
`theme.json`; that URL is fetched server-side by the WP HTTP API when
the Font Library generates the CSS. Several themes register an admin
endpoint that takes the source URL as a POST parameter, enabling SSRF
to internal hosts (cloud metadata, internal services).

Passive: fingerprint installs that have ANY theme.json setting reachable
via the REST `/wp-json/wp/v2/global-styles/` endpoint. Surface medium
if the global-styles JSON contains a remote fontFamilies.source URL —
that's the operator's CONFIGURED state, which means the SSRF surface
is active.
"""
from __future__ import annotations

import json

from ..http import Client
from ..models import Finding


_PATHS = (
    "/wp-json/wp/v2/global-styles",
    "/wp-json/wp/v2/global-styles/themes/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PATHS:
        step(f"theme.json fonts probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        # Quick check for HTTP-sourced fonts
        if "fontFamilies" not in r.text:
            continue
        try:
            data = json.loads(r.text)
        except (ValueError, AttributeError):
            continue
        # data may be a list (themes) or dict (single style). Normalise.
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            settings = (item.get("settings") or {}).get("typography", {})
            for ff in settings.get("fontFamilies", []) or []:
                src = ff.get("source") if isinstance(ff, dict) else None
                if src and isinstance(src, str) and src.startswith(("http://", "https://")):
                    findings.append(Finding(
                        severity="medium",
                        title="theme.json registers remote font-source URL — verify Font Library SSRF guard",
                        evidence=(
                            f"REST {path} returned a fontFamilies entry with\n"
                            f"  source = {src[:200]}\n"
                            "If your theme exposes an admin endpoint that POSTs a\n"
                            "user-controlled source URL, an attacker can probe\n"
                            "internal hosts via the WP HTTP API."
                        ),
                        remediation=(
                            "1. Audit any theme endpoint that accepts a font\n"
                            "   source URL — must validate via wp_http_validate_url()\n"
                            "   AND check the resolved IP isn't RFC1918/link-local.\n"
                            "2. WP core itself doesn't expose the field publicly;\n"
                            "   the risk is custom plugin / theme code.\n"
                            "3. Disable wp_http_validate_url filter overrides."
                        ),
                        url=client.url(path),
                        extra={"source": src[:200]},
                    ))
                    return findings
    return findings
