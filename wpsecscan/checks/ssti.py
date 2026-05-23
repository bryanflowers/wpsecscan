"""Server-Side Template Injection probe.

Sends a few computational expressions in template-engine syntax to discovered
query parameters. If the response reflects the EVALUATED result (e.g. `49` for
`{{7*7}}`), the parameter is being passed unsanitized into a templating system.

Covers Jinja2/Twig (`{{...}}`), ERB/Underscore (`<%= ... %>`), Tornado
(`{% ... %}`), Velocity/JSP/EL (`${...}`), Mako (`${...}`), Java EL spring
(`#{...}`), JSF (`#{...}`), Twig math (`{{ 7*7 }}`).

Aggressive-only.
"""
from __future__ import annotations

import re
import secrets

from ..http import Client
from ..models import Finding

# (template-syntax expression, expected reflected value)
# Use a multiplication that's unlikely to appear by accident: 7777 * 7 = 54439.
PAYLOADS = (
    ("{{7777*7}}",       "54439", "Jinja2/Twig"),
    ("${7777*7}",         "54439", "EL / Velocity / Mako"),
    ("<%= 7777*7 %>",    "54439", "ERB / EJS"),
    ("#{7777*7}",         "54439", "Ruby/JSF EL"),
    ("${{7777*7}}",       "54439", "GitHub Actions / nested"),
    ("@{7777*7}",         "54439", "Razor"),
    ("[[7777*7]]",        "54439", "Smarty / 2-bracket"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="SSTI probe skipped (requires --aggressive)",
                evidence="This sends `{{7777*7}}` style template-syntax payloads to discovered params.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Discover candidate URLs + params from a few pages. Cheap heuristic: pull
    # `?foo=...` from links + the homepage's own URL.
    candidate_params: set[tuple[str, str]] = set()  # (path, param_name)
    for path in ("/", "/?p=1", "/?cat=1", "/?s=test", "/?author=1"):
        if "?" in path:
            base, q = path.split("?", 1)
            for kv in q.split("&"):
                if "=" in kv:
                    name = kv.split("=", 1)[0]
                    candidate_params.add((base or "/", name))

    # Also harvest from links on the homepage
    step("collecting candidate params from /...")
    r = await client.get("/")
    if r is not None and r.text:
        for m in re.findall(r'href=["\']([^"\']+\?[^"\']+)', r.text[:80000]):
            try:
                from urllib.parse import urlparse, parse_qs
                u = urlparse(m)
                p = u.path or "/"
                for k in parse_qs(u.query or "").keys():
                    if 1 <= len(k) <= 30:
                        candidate_params.add((p, k))
            except (ValueError, TypeError):
                continue

    if not candidate_params:
        findings.append(
            Finding(
                severity="info",
                title="SSTI probe skipped — no candidate query parameters found",
                evidence="No URL params discovered on probed pages.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    leaks: list[tuple[str, str, str, str]] = []  # (path, param, payload, engine)
    canary_prefix = secrets.token_hex(3)  # not used directly but bounds the loop's identity

    for path, name in list(candidate_params)[:8]:  # cap
        for payload, expected, engine in PAYLOADS:
            step(f"SSTI probe: {path}?{name}={payload[:20]} ({engine})...")
            r = await client.get(path, params={name: payload})
            if r is None or not r.text:
                continue
            body = r.text[:50000]
            # Must contain the evaluated result AND NOT contain our raw payload
            # (a site that just reflects unfiltered would show the literal `{{...}}`)
            if expected in body and payload not in body:
                leaks.append((path, name, payload, engine))
                break  # found one engine for this param, no need to test more

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title=f"No SSTI detected ({len(candidate_params)} params × {len(PAYLOADS)} payloads tested)",
                evidence=f"Canary `{canary_prefix}` — no template engine evaluated our expression.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for path, name, payload, engine in leaks:
        findings.append(
            Finding(
                severity="critical",
                title=f"SSTI confirmed at {path}?{name}= ({engine} family)",
                evidence=(
                    f"Sent: ?{name}={payload}\n"
                    f"Response contained the evaluated result (54439) without the raw payload.\n"
                    f"Suspect template engine: {engine}\n\n"
                    "SSTI in WordPress is rare in core but happens in plugins that use Twig/Smarty for "
                    "email templates or page builders. From SSTI to RCE is usually one Jinja2-style "
                    "`{{cycler.__init__.__globals__.os.popen('id').read()}}` jump."
                ),
                remediation=(
                    "Audit the plugin handling this parameter. NEVER pass user input directly into "
                    "`Twig::render`, `Smarty::fetch`, etc. Use the templating engine's data-binding API "
                    "(pass user input as a variable, not as part of the template string)."
                ),
                url=client.url(path),
            )
        )
    return findings
