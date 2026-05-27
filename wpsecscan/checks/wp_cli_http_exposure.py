"""A7 (v2.6.0) — WP-CLI-over-HTTP endpoint exposure.

Several managed-WP hosts (Pantheon, WP Engine SSH gateway, Kinsta,
Cloudways, Local-by-Flywheel "Live Link") expose a WP-CLI-shaped HTTP
endpoint so the operator can run CLI commands without SSH. These
endpoints accept a serialised command and authenticate via either:

  • A static path-segment token (`/wp-cli/{token}/cmd`).
  • A POST body field (`/wp-cli-server` with `token=...`).
  • Basic Auth on the path (`/wp-admin/maintenance/wp-cli`).

When the endpoint is reachable without auth (mis-configured custom
plugin, leftover dev tool), the host has an interactive shell. We
probe the common paths defensively and surface a critical finding
on any 200 response. No payload submission — pure existence probe.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PATHS = (
    "/wp-cli-server",
    "/wp-cli/run",
    "/wp-admin/maintenance/wp-cli",
    "/wp-admin/wp-cli.php",
    "/wp-content/wp-cli-handler.php",
    "/wp-content/mu-plugins/wp-cli-http.php",
    "/?wp-cli=1",
    "/?wpcli=help",
    "/wp-json/wp-cli/v1/run",
    "/wp-json/managed/v1/cli",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PATHS:
        step(f"wp-cli probe: {path}")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code == 200:
            body = (r.text or "")[:300]
            # Filter false positives — many sites return a generic 200
            # page on unknown query strings. Require an actual signal.
            looks_like_cli = any(s in body.lower() for s in
                                  ("wp-cli", "wpcli", "command", "usage:",
                                   "wp cli", "phar", "wp_cli"))
            if not looks_like_cli:
                continue
            findings.append(Finding(
                severity="critical",
                title=f"WP-CLI-over-HTTP endpoint reachable: {path}",
                evidence=(
                    f"GET {path} → HTTP 200, response body contains WP-CLI "
                    f"keyword.\n"
                    f"Excerpt: {body}\n"
                    f"If this endpoint accepts unauthenticated POSTs with a "
                    f"command body, an attacker has a remote shell on the "
                    f"WordPress install (equivalent to wp-config.php access)."
                ),
                remediation=(
                    "1. IMMEDIATE: block " + path + " at the WAF until verified.\n"
                    "2. Determine which plugin / mu-plugin registered the endpoint "
                    "(`grep -r \"" + path.lstrip('/') + "\" wp-content/`).\n"
                    "3. Require auth on the endpoint: either Basic Auth at the "
                    "web-server level, IP allow-list, or a one-time bearer token "
                    "rotated daily.\n"
                    "4. Audit web-server access logs for prior unauthorised hits."
                ),
                url=client.url(path),
                extra={"path": path, "category": "remote-shell"},
            ))
        elif r.status_code in (401, 403):
            findings.append(Finding(
                severity="low",
                title=f"WP-CLI-over-HTTP endpoint present (auth required): {path}",
                evidence=f"GET {path} → HTTP {r.status_code} (auth gate present).",
                remediation=(
                    "Endpoint correctly auth-gated. Periodically audit:\n"
                    "  - that the token isn't a static long-lived value\n"
                    "  - that IP allow-list is current\n"
                    "  - that the auth check happens BEFORE command parsing"
                ),
                url=client.url(path),
                extra={"path": path, "status": r.status_code},
            ))
    return findings
