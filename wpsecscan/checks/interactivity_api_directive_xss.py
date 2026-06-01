"""F66 (v2.8.3) — WP 6.5+ Interactivity API directive-XSS surface.

The Interactivity API (`@wordpress/interactivity`) renders dynamic
behavior via `data-wp-on`, `data-wp-bind`, and `data-wp-context`
directives. Custom block plugins that interpolate user-controlled
strings into these directive values without HTML-escaping create a
real XSS vector (the directive value is parsed as a JS expression).

This check is DEFENSIVE: we GET the homepage with a URL canary, look
for the canary surfacing inside a `data-wp-*` directive value, and
emit a high-severity finding if found. We do NOT attempt to bypass
sanitization — we just verify whether the page's directive surface
is reflection-aware.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_CANARY = "WPSECSCAN_XX_77"
_DIRECTIVE_RE = re.compile(
    r'data-wp-(?:on|bind|context|class|style|text|each|init|run|key)'
    r'(?:--\w+)?="([^"]*)"',
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F66: probing Interactivity API directives for XSS reflection")
    # Reflect the canary into a query param + a search-style endpoint;
    # the Interactivity API often binds form input or query state into
    # directives via the `data-wp-context` JSON object.
    probe_paths = [
        f"/?wpsec={_CANARY}",
        f"/?s={_CANARY}",
        f"/page/1?ref={_CANARY}",
    ]
    findings: list[Finding] = []
    saw_interactivity = False
    for path in probe_paths:
        r = await client.get(path)
        if r is None:
            continue
        body = r.text or ""
        # Quick fingerprint: site uses the Interactivity API at all?
        if "data-wp-" in body or "@wordpress/interactivity" in body:
            saw_interactivity = True
        # Find any directive whose value contains the canary literally
        # (i.e. not escaped to `&quot;` or HTML-encoded).
        for m in _DIRECTIVE_RE.finditer(body):
            if _CANARY in m.group(1):
                findings.append(Finding(
                    severity="high",
                    title="F66: Interactivity API directive reflects URL input without escaping",
                    evidence=(
                        f"GET {path} → canary {_CANARY!r} appears verbatim "
                        f"inside a `data-wp-*` directive value: "
                        f"`{m.group(0)[:160]}`"),
                    remediation=(
                        "Audit your block plugin's directive-binding code. "
                        "Run any user-controlled string through "
                        "`wp_kses_post()` (PHP) or `escape-html` (JS) BEFORE "
                        "interpolating into a `data-wp-*` attribute. The "
                        "Interactivity API parses directive values as JS "
                        "expressions; unescaped strings become injection "
                        "vectors."),
                    url=ctx["target"]))
                break  # one finding per probe path is enough
    if not saw_interactivity:
        findings.append(Finding(
            severity="info",
            title="F66: Interactivity API not detected (no data-wp-* attrs)",
            evidence="None of the 3 probe responses contained any `data-wp-` directive.",
            remediation="No action needed; check only applies to WP 6.5+ FSE/Block sites that opted into the Interactivity API.",
            url=ctx["target"]))
    return findings
