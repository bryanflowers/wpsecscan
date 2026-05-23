"""Comprehensive /.well-known/ enumeration.

RFC 8615 reserves /.well-known/ for site metadata. Many WordPress sites
expose more than they realise:
  - SSO discovery (openid-configuration, oauth-authorization-server)
  - Mobile app deep-link config (apple-app-site-association, assetlinks.json)
  - Matrix federation (matrix/server, matrix/client)
  - WebFinger (account discovery)
  - host-meta (XRD service docs)

This check is purely informational — we report what's exposed; the user
decides what's intentional.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (path, what-it-reveals)
WELL_KNOWN_PATHS = (
    ("/.well-known/host-meta", "XRD service-discovery doc (legacy)"),
    ("/.well-known/host-meta.json", "JSON XRD service-discovery doc"),
    ("/.well-known/openid-configuration", "OpenID Connect provider config — auth endpoints, scopes, key URIs"),
    ("/.well-known/oauth-authorization-server", "OAuth 2.0 server metadata (RFC 8414)"),
    ("/.well-known/webfinger", "WebFinger account discovery"),
    ("/.well-known/change-password", "RFC 8484 password-change URL (good practice)"),
    ("/.well-known/dnt-policy.txt", "EFF Do-Not-Track policy"),
    ("/.well-known/apple-app-site-association", "iOS Universal Links config"),
    ("/.well-known/assetlinks.json", "Android App Links config"),
    ("/.well-known/matrix/server", "Matrix federation server delegation"),
    ("/.well-known/matrix/client", "Matrix client delegation"),
    ("/.well-known/jwks.json", "JSON Web Key Set — public signing keys"),
    ("/.well-known/nodeinfo", "Fediverse node info"),
    ("/.well-known/mta-sts.txt", "MTA-STS mail-security policy"),
    ("/.well-known/discord", "Discord linked-role verification"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    found: list[tuple[str, str, int, int]] = []  # path, label, status, size
    for path, label in WELL_KNOWN_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.content:
            continue
        size = len(r.content)
        if size < 10:  # empty/placeholder
            continue
        found.append((path, label, r.status_code, size))

    if not found:
        findings.append(
            Finding(
                severity="info",
                title="No /.well-known/ resources exposed",
                evidence=f"Probed {len(WELL_KNOWN_PATHS)} well-known paths; none returned a non-empty 200.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Sensitive ones get a low/medium flag; informational ones are info.
    sensitive_paths = {
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/.well-known/webfinger",
    }
    for path, label, status, size in found:
        sev = "low" if path in sensitive_paths else "info"
        findings.append(
            Finding(
                severity=sev,
                title=f"Well-known resource exposed: {path}",
                evidence=f"HTTP {status} ({size} bytes). {label}",
                remediation=(
                    "If intentional (SSO, mobile app, federation), no action. "
                    "If you don't know what this is, the plugin/theme that added it is the culprit — "
                    "removing the plugin removes the file. Sensitive configs (openid-configuration, "
                    "jwks.json) reveal your auth architecture."
                ),
                url=client.url(path),
            )
        )
    return findings
