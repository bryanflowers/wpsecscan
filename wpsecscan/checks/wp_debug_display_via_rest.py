"""Detect WP_DEBUG_DISPLAY=true via deliberately malformed REST request.

POST malformed JSON to /wp-json/wp/v2/posts (no auth). A correctly-
configured server returns a clean JSON error. A misconfigured server
(WP_DEBUG_DISPLAY=true in production) leaks the PHP stack trace, file
paths, and framework versions in the 4xx/5xx response body.

Distinct from `debug_leaks.py` which probes /?p[]=1 — this hits the
REST router specifically, which uses different error machinery.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_PHP_TRACE_RE = re.compile(
    r"(?:Fatal error|Stack trace:|Uncaught\s+(?:Error|Exception)|"
    r"(?:Warning|Notice|Deprecated)\s*:\s*.+?\s+in\s+/(?:home|var|usr|opt)/\S+\.\S+\s+on\s+line\s+\d+)",
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("POSTing malformed JSON to /wp-json/wp/v2/posts...")
    # Deliberately broken: invalid JSON body. WP should return 400 with a
    # tidy JSON error. WP_DEBUG_DISPLAY=true leaks the PHP error in the
    # response body before WP's JSON marshalling gets to it.
    r = await client.post("/wp-json/wp/v2/posts",
                          content=b"{this is: not, json}",
                          headers={"Content-Type": "application/json"})
    if r is None:
        return findings
    body = (r.text or "")[:5000]
    if not body:
        return findings
    m = _PHP_TRACE_RE.search(body)
    if not m:
        return findings
    snippet = m.group(0)
    findings.append(Finding(
        severity="medium",
        title="WP_DEBUG_DISPLAY=true leaks PHP error via REST API malformed-body response",
        evidence=(
            f"POST /wp-json/wp/v2/posts with invalid JSON → HTTP {r.status_code} "
            "with a PHP error/stack-trace shape in the body:\n"
            f"  {snippet[:200]}\n\n"
            "This indicates `define('WP_DEBUG_DISPLAY', true)` in wp-config.php (or "
            "`display_errors = On` in php.ini) for the production environment. PHP "
            "error output should never appear in HTTP responses on a public site — "
            "it leaks absolute filesystem paths, framework versions, and the "
            "specific PHP version in use."
        ),
        remediation=(
            "In wp-config.php:\n"
            "  define('WP_DEBUG',         false);   // or true with the next two off\n"
            "  define('WP_DEBUG_DISPLAY', false);\n"
            "  define('WP_DEBUG_LOG',     true);    // log to file instead\n"
            "In php.ini (and any per-vhost override):\n"
            "  display_errors = Off\n"
            "  log_errors     = On\n"
            "Then verify by re-running this check or POSTing the same broken JSON manually."
        ),
        url=client.url("/wp-json/wp/v2/posts"),
    ))
    return findings
