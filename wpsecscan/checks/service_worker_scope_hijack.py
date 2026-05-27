"""A29 (v2.6.0) — service-worker scope-hijack risk.

A service worker registered with `scope: "/"` intercepts navigation
requests for the entire origin. When a plugin folder ships a SW with
scope "/", that PLUGIN gains the ability to MITM every page on the
site (modify HTML, inject scripts, exfil cookies via fetch handlers).
If the plugin is later compromised, it has total client-side control.

Passive: GET /sw.js + /service-worker.js + the canonical PWA paths,
look at the `Service-Worker-Allowed` response header or the SW's
own `self.registration.scope` reference; flag medium when the SW
registered from a non-root URL takes scope "/".
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_SW_PATHS = (
    "/wp-content/plugins/super-progressive-web-apps/sw.js",
    "/wp-content/plugins/pwa-for-wp/sw.js",
    "/wp-content/plugins/simple-pwa/sw.js",
    "/wp-content/plugins/wp-pwa/sw.js",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _SW_PATHS:
        step(f"SW scope probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        # If served from a /wp-content/plugins/.../ path, the SW's natural
        # scope is that subfolder; using scope:"/" requires a special
        # `Service-Worker-Allowed: /` header.
        allowed = r.headers.get("service-worker-allowed", "")
        body = (r.text or "")[:5000]
        body_scope = "/" in body and "scope" in body.lower()

        if allowed.strip() == "/" or body_scope:
            findings.append(Finding(
                severity="medium",
                title=f"Plugin-shipped service worker claims origin-wide scope: {path}",
                evidence=(
                    f"GET {path} returns 200.\n"
                    f"Service-Worker-Allowed header: {allowed!r}\n"
                    "SW body references root scope. If this plugin is later\n"
                    "compromised (supply-chain or local code-tamper), it can\n"
                    "MITM every page on the origin via fetch handler."
                ),
                remediation=(
                    "1. Restrict the SW's scope to its own folder by NOT\n"
                    "   sending the Service-Worker-Allowed: / header.\n"
                    "2. If a root-scope SW is required for the PWA install,\n"
                    "   move it to the web root (/sw.js) so its provenance\n"
                    "   matches the operator's expectations.\n"
                    "3. Pin the SW's source to a specific git SHA in the\n"
                    "   plugin update policy."
                ),
                url=client.url(path),
                extra={"path": path, "allowed_header": allowed},
            ))
    return findings
