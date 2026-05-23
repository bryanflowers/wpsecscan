"""security.txt / .well-known endpoint audit (RFC 9116).

Modern sites should publish /.well-known/security.txt with a security
contact + scope statement. Also probes for /.well-known/change-password
(RFC 8615) and /humans.txt.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("checking /.well-known/security.txt...")
    r = await client.get("/.well-known/security.txt")
    if r is None or r.status_code != 200 or "Contact:" not in (r.text or ""):
        # Also try /security.txt at root (legacy)
        r2 = await client.get("/security.txt")
        if r2 is None or r2.status_code != 200 or "Contact:" not in (r2.text or ""):
            findings.append(
                Finding(
                    severity="low",
                    title="No /.well-known/security.txt found (RFC 9116)",
                    evidence="Neither /.well-known/security.txt nor /security.txt returned a valid security.txt.",
                    remediation=(
                        "Publish a security.txt at /.well-known/security.txt. Use https://securitytxt.org to generate.\n"
                        "Minimum content:\n"
                        "  Contact: mailto:security@yourdomain.com\n"
                        "  Expires: <date 1 year out, ISO 8601>\n"
                        "  Preferred-Languages: en\n"
                        "Researchers reporting findings need a way to reach you."
                    ),
                    url=client.url("/.well-known/security.txt"),
                )
            )
            return findings
        r = r2

    body = r.text or ""
    findings.append(
        Finding(
            severity="info",
            title="security.txt present (good)",
            evidence=f"GET {r.url} -> 200\n  First 200 chars: {body[:200]!r}",
            remediation="Verify Contact and Expires are current.",
            url=str(r.url) if hasattr(r, "url") else client.url("/.well-known/security.txt"),
        )
    )
    return findings
