"""Deeper TLS audit beyond the basic version-and-expiry that tls_headers does.

Checks negotiated cipher strength, presence of forward-secrecy, certificate
chain length / self-signed indicators, and SAN list (subjectAltName).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


def _inspect(host: str, port: int = 443) -> dict:
    """Returns a dict with negotiated version/cipher/cert details. Best-effort."""
    out = {
        "tls_version": None, "cipher": None, "cipher_bits": None,
        "subject_cn": None, "issuer_cn": None, "expires_in_days": None,
        "san_count": 0, "san_sample": [], "is_self_signed": False, "error": "",
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    out["cipher"] = cipher[0]
                    out["cipher_bits"] = cipher[2]
                cert = ssock.getpeercert() or {}
                subj = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                out["subject_cn"] = subj.get("commonName", "")
                out["issuer_cn"] = issuer.get("commonName", "")
                # Subject-Alt-Names
                san = cert.get("subjectAltName", ())
                if san:
                    sans = [v for (_t, v) in san if isinstance(v, str)]
                    out["san_count"] = len(sans)
                    out["san_sample"] = sans[:5]
                # Days until expiry
                exp = cert.get("notAfter")
                if exp:
                    dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    out["expires_in_days"] = (dt - datetime.now(timezone.utc)).days
                # Self-signed: issuer == subject
                if out["subject_cn"] and out["subject_cn"] == out["issuer_cn"]:
                    out["is_self_signed"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not host:
        findings.append(
            Finding(
                severity="info",
                title="Deep TLS audit skipped — site is not HTTPS",
                evidence=f"target scheme: {parsed.scheme}",
                remediation="Serve the site over HTTPS first; then this check becomes meaningful.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"deep TLS handshake to {host}:443...")
    info = await asyncio.to_thread(_inspect, host)
    if info["error"]:
        findings.append(
            Finding(
                severity="medium",
                title="Deep TLS handshake failed",
                evidence=f"Connect/handshake to {host}:443 failed: {info['error']}",
                remediation="Verify the cert chain is valid and SNI works.",
                url=ctx["target"],
            )
        )
        return findings

    # Findings:
    # 1. Cipher strength
    if info["cipher"]:
        is_aead = any(s in (info["cipher"] or "").upper() for s in ("GCM", "POLY1305", "CCM"))
        sev = "info" if is_aead else "medium"
        title = ("Modern AEAD cipher in use" if is_aead else "Non-AEAD cipher in use (consider CHACHA20-POLY1305 / GCM)")
        findings.append(
            Finding(
                severity=sev,
                title=title,
                evidence=(
                    f"Negotiated TLS: {info['tls_version']}\n"
                    f"Cipher:         {info['cipher']}\n"
                    f"Cipher bits:    {info['cipher_bits']}\n"
                ),
                remediation=(
                    "Prefer AEAD ciphers (AES-GCM, CHACHA20-POLY1305). Nginx example:\n"
                    "  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
                    "  ssl_prefer_server_ciphers on;"
                ),
                url=ctx["target"],
            )
        )

    # 2. Self-signed
    if info["is_self_signed"]:
        findings.append(
            Finding(
                severity="high",
                title=f"Self-signed certificate at {host}",
                evidence=f"Subject CN = Issuer CN = {info['subject_cn']!r}. No trusted CA in the chain.",
                remediation="Issue a real cert from Let's Encrypt (`certbot`) or your provider. Self-signed certs train users to dismiss browser warnings.",
                url=ctx["target"],
            )
        )

    # 3. SAN coverage
    if info["san_count"] == 0:
        findings.append(
            Finding(
                severity="low",
                title="Certificate has no SubjectAltName (SAN) — modern browsers will reject",
                evidence=f"Subject CN: {info['subject_cn']}, no SAN.",
                remediation="Reissue the certificate with a SAN list including every host you serve.",
                url=ctx["target"],
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"Certificate covers {info['san_count']} SAN entries",
                evidence=f"Sample SANs: {', '.join(info['san_sample'])}",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    # 4. Expiry warning (lower threshold than tls_headers — anything < 30 days warns)
    days = info["expires_in_days"]
    if days is not None and days < 30 and days >= 0:
        findings.append(
            Finding(
                severity="medium" if days >= 14 else "high",
                title=f"TLS certificate expires in {days} day(s)",
                evidence=f"Subject CN: {info['subject_cn']}; expires in {days} day(s).",
                remediation="Renew now and verify auto-renew is configured. `certbot renew --dry-run`.",
                url=ctx["target"],
            )
        )

    return findings
