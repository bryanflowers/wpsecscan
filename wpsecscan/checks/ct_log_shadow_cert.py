"""A31 (v2.6.0) — Certificate Transparency log shadow-cert.

Sibling of the existing `ct_log_recent_certs` check, but tighter:
specifically flag certificates issued for the apex domain by a CA
whose name doesn't match the CA on the LIVE cert. If the live site
uses Let's Encrypt and the CT log shows a recent Sectigo or GoGetSSL
cert for the same apex, that's a strong signal of a shadow-cert
attack (attacker registered a cert behind the operator's back).

Uses crt.sh (free CT-log search) for the lookup.
"""
from __future__ import annotations

import json
import ssl
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


async def _live_cert_issuer(host: str) -> str:
    """Connect to host:443 and return the certificate's issuer Org."""
    try:
        import socket
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                for entry in cert.get("issuer", []):
                    for k, v in entry:
                        if k == "organizationName":
                            return v
    except (OSError, ssl.SSLError, ValueError):
        pass
    return ""


async def check(client: Client, ctx_: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx_.get("step") or (lambda _s: None)

    host = urlparse(client.base_url).hostname or ""
    if not host:
        return findings

    step(f"CT shadow-cert: live cert issuer for {host}")
    live_issuer = await _live_cert_issuer(host)
    if not live_issuer:
        return findings  # couldn't probe TLS

    step(f"CT shadow-cert: crt.sh lookup for {host}")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15.0) as ext:
            r = await ext.get(f"https://crt.sh/?q={host}&output=json")
            if r.status_code != 200:
                return findings
            entries = r.json() if r.text else []
    except Exception:  # noqa: BLE001
        return findings

    if not isinstance(entries, list):
        return findings

    foreign_issuers: dict[str, list[str]] = {}
    for e in entries[:50]:
        if not isinstance(e, dict):
            continue
        issuer = (e.get("issuer_name") or "").strip()
        common_name = e.get("common_name", "")
        # Match only certs that name the apex (not random subdomains)
        if host not in common_name and host not in (e.get("name_value") or ""):
            continue
        # Skip exact-issuer match — that's our own renewal history
        if live_issuer.lower() in issuer.lower():
            continue
        foreign_issuers.setdefault(issuer, []).append(e.get("not_before", ""))

    for issuer, dates in foreign_issuers.items():
        findings.append(Finding(
            severity="high",
            title=f"CT log shows a non-live-issuer cert for {host}: {issuer[:80]}",
            evidence=(
                f"Live site cert: issuer = {live_issuer!r}\n"
                f"CT-log entry shows a separate cert issued by:\n  {issuer}\n"
                f"Issuance dates: {dates[:3]}\n"
                "A foreign-CA cert on the same apex is a shadow-cert signal "
                "(an attacker may have completed domain validation behind "
                "your back, perhaps via a stolen DNS API key)."
            ),
            remediation=(
                "1. Verify whether YOU issued this cert (CDN, separate\n"
                "   email/DNS provider, an old monitoring tool).\n"
                "2. If not, treat as a serious incident: rotate DNS API\n"
                "   credentials NOW; audit DNS records for unauthorised\n"
                "   _acme-challenge TXT records.\n"
                "3. Add the apex to a CAA record naming ONLY your real CA\n"
                "   (e.g. `example.com. CAA 0 issue \"letsencrypt.org\"`).\n"
                "4. Subscribe to crt.sh email notifications for the apex."
            ),
            url=f"https://crt.sh/?q={host}",
            extra={"live_issuer": live_issuer, "shadow_issuer": issuer},
        ))
    return findings
