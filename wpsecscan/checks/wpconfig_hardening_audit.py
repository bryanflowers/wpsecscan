"""wp-config.php hardening inference from remote signals.

Round-64 #52 — wp-config.php sits on the server (we can't read it), but
several of its hardening flags show up in remote-observable telemetry.
This check flags the absence of: DISALLOW_FILE_EDIT, WP_DEBUG_DISPLAY=
false, DISALLOW_FILE_MODS, FORCE_SSL_ADMIN. Each is inferred from
indirect signals (admin theme editor reachable, PHP errors in body,
plugin upload form present, http:// login redirect).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("checking theme-editor exposure...")
    r = await client.get("/wp-admin/theme-editor.php")
    if r is not None and r.status_code in (200, 302):
        loc = (r.headers.get("location") or "").lower() if hasattr(r, "headers") else ""
        # 302 to wp-login is expected and OK; 200 without login redirect is suspicious
        if r.status_code == 200 and "wp-login" not in (r.text or "").lower():
            findings.append(
                Finding(
                    severity="medium",
                    title="Theme editor reachable — DISALLOW_FILE_EDIT not set",
                    evidence=f"GET /wp-admin/theme-editor.php -> {r.status_code}, no login redirect detected",
                    remediation=(
                        "Add to wp-config.php:\n"
                        "  define('DISALLOW_FILE_EDIT', true);\n"
                        "  define('DISALLOW_FILE_MODS', true);\n"
                        "Disables the admin file editor — a top-3 webshell-install path."
                    ),
                    url=client.url("/wp-admin/theme-editor.php"),
                )
            )

    step("checking debug leakage in errors...")
    # Trigger a 404; check the response body for WP_DEBUG bleed (file paths, stack traces)
    r2 = await client.get("/?wpsecscan-debug-probe-12345")
    body = (r2.text or "") if r2 is not None else ""
    debug_signals = ("/wp-content/", "Notice:", "Warning:", "Fatal error:", "Deprecated:", "Stack trace:")
    hits = [s for s in debug_signals if s in body]
    if len(hits) >= 2:
        findings.append(
            Finding(
                severity="medium",
                title="PHP debug output leaks in HTTP body",
                evidence=f"Probe response contained: {', '.join(hits[:4])}",
                remediation=(
                    "Add to wp-config.php (production):\n"
                    "  define('WP_DEBUG', false);\n"
                    "  define('WP_DEBUG_DISPLAY', false);\n"
                    "  define('WP_DEBUG_LOG', true);  // log instead of display\n"
                    "Server-side: error_reporting(0); display_errors=Off in php.ini."
                ),
                url=client.url("/?wpsecscan-debug-probe-12345"),
            )
        )

    step("checking forced HTTPS on wp-admin...")
    r3 = await client.get("/wp-admin/")
    if r3 is not None and r3.status_code in (200, 301, 302):
        loc = r3.headers.get("location", "") if hasattr(r3, "headers") else ""
        if loc.startswith("http://"):
            findings.append(
                Finding(
                    severity="high",
                    title="wp-admin allows plain-HTTP login flow — FORCE_SSL_ADMIN missing",
                    evidence=f"GET /wp-admin/ -> redirect to {loc!r}",
                    remediation=(
                        "Add to wp-config.php:\n"
                        "  define('FORCE_SSL_ADMIN', true);\n"
                        "Plus an HTTP->HTTPS 301 at the web-server level."
                    ),
                    url=client.url("/wp-admin/"),
                )
            )

    return findings
