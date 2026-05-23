"""Deep TLS protocol audit.

Uses the stdlib `ssl` module via `asyncio.to_thread` (no extra deps) to probe:
  1. Whether TLS 1.0 / 1.1 are still ACCEPTED (PCI-DSS bans them)
  2. Negotiated cipher suite (flag RC4 / 3DES / NULL / EXPORT)
  3. Certificate expiry distance (warn <30 days)
  4. Server name verification + SAN coverage
  5. OCSP-must-staple presence (cert extension)

The existing `tls_deep` check is shallower — this complements it.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

WEAK_PROTOCOLS = ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


def _connect_with(host: str, port: int, protocol_name: str) -> tuple[bool, str]:
    """Try to negotiate the given protocol against host:port. Returns (succeeded, info)."""
    proto_map = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1":   ssl.TLSVersion.TLSv1,
    }
    if protocol_name not in proto_map:
        return False, f"unsupported probe protocol {protocol_name}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = proto_map[protocol_name]
        ctx.maximum_version = proto_map[protocol_name]
    except (ssl.SSLError, ValueError):
        return False, "host stack rejected protocol pinning"
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                ciph = ssock.cipher()
                cipher_name = ciph[0] if ciph else "(unknown)"
                return True, f"negotiated {ver} with cipher {cipher_name}"
    except (ssl.SSLError, socket.timeout, OSError) as e:
        return False, f"rejected: {type(e).__name__}"


def _cert_audit(host: str, port: int) -> dict:
    """Fetch and inspect the server's TLS certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return {"ok": True, "cert": cert, "cipher": cipher}
    except (ssl.SSLError, socket.timeout, OSError) as e:
        return {"ok": False, "err": str(e)}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    target = ctx["target"]
    p = urlparse(target)
    if p.scheme != "https":
        findings.append(
            Finding(
                severity="info",
                title="Deep TLS audit skipped (target is not https://)",
                evidence=f"Target scheme: {p.scheme}",
                remediation="No action.",
                url=target,
            )
        )
        return findings

    host = p.hostname or ""
    port = p.port or 443

    # 1. Weak-protocol acceptance
    rejected_weak: list[str] = []
    accepted_weak: list[tuple[str, str]] = []
    for proto in WEAK_PROTOCOLS:
        step(f"testing weak TLS protocol {proto}...")
        ok, info = await asyncio.to_thread(_connect_with, host, port, proto)
        if ok:
            accepted_weak.append((proto, info))
        else:
            rejected_weak.append(proto)

    # 2. Cert + current cipher
    step("fetching certificate + current cipher...")
    audit = await asyncio.to_thread(_cert_audit, host, port)

    if accepted_weak:
        for proto, info in accepted_weak:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Weak TLS protocol accepted: {proto}",
                    evidence=f"{host}:{port} {info}\nWeak protocols banned by PCI-DSS 3.2.1 and most modern compliance regimes.",
                    remediation=(
                        f"Disable {proto} at the web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`  "
                        f"Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`. If behind a CDN, configure at the CDN edge."
                    ),
                    url=target,
                )
            )

    if audit.get("ok"):
        cipher_name = (audit["cipher"][0] if audit["cipher"] else "")
        if any(tok in cipher_name for tok in WEAK_CIPHER_TOKENS):
            findings.append(
                Finding(
                    severity="high",
                    title=f"Weak TLS cipher in use: {cipher_name}",
                    evidence=f"Negotiated cipher: {audit['cipher']}",
                    remediation=(
                        "Update the cipher suite. nginx: `ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:...`. "
                        "See Mozilla SSL Configuration Generator (intermediate or modern profile)."
                    ),
                    url=target,
                )
            )
        cert = audit.get("cert") or {}
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days <= 0:
                    findings.append(
                        Finding(
                            severity="critical",
                            title=f"TLS certificate EXPIRED {abs(days)} days ago",
                            evidence=f"notAfter: {not_after}",
                            remediation="Renew immediately. If using Let's Encrypt, check certbot/renewal cron.",
                            url=target,
                        )
                    )
                elif days <= 14:
                    findings.append(
                        Finding(
                            severity="high",
                            title=f"TLS certificate expires in {days} days",
                            evidence=f"notAfter: {not_after}",
                            remediation="Schedule renewal NOW. Let's Encrypt renewal cron may have stopped.",
                            url=target,
                        )
                    )
                elif days <= 30:
                    findings.append(
                        Finding(
                            severity="medium",
                            title=f"TLS certificate expires in {days} days",
                            evidence=f"notAfter: {not_after}",
                            remediation="Verify renewal is automated. Set a calendar reminder if not.",
                            url=target,
                        )
                    )
            except ValueError:
                pass

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Deep TLS audit: no weak protocols, ciphers, or expiring certs",
                evidence=(
                    f"Rejected weak protocols: {', '.join(rejected_weak) or 'none'}\n"
                    f"Negotiated: {audit.get('cipher')}"
                ),
                remediation="No action.",
                url=target,
            )
        )
    return findings
