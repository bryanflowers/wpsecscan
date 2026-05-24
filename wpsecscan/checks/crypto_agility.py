"""Round-59 #47-51 — Crypto agility audit.

#47 Post-quantum cipher — does the server advertise any hybrid PQ
   key-exchange (X25519MLKEM768 / X25519Kyber768Draft00) in TLS?
#48 Hybrid TLS 1.3 — confirm TLS 1.3 with hybrid KEX
#49 Crypto inventory — list cert SAN, public-key algorithm + size, sig
   algorithm, OCSP-must-staple flag
#50 RSA key size — flag <2048 bit RSA certs (still common on old hosts)
#51 Curve preference — server advertises which ECDH curves?

All best-effort via stdlib `ssl` + optional `cryptography` parse. We
avoid pulling in heavy deps.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


def _gather_tls(host: str, port: int = 443, timeout: float = 6.0) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                version = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)
                shared = ssock.shared_ciphers() or []
                return {
                    "cert_der": cert,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "shared_count": len(shared),
                }
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError):
        return None


def _parse_cert(der: bytes) -> dict:
    out = {"subject": "", "sans": [], "key_alg": "", "key_bits": 0,
            "sig_alg": "", "must_staple": False}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        cert = x509.load_der_x509_certificate(der)
        out["subject"] = cert.subject.rfc4514_string()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["sans"] = [n.value for n in san.value]
        except x509.ExtensionNotFound:
            pass
        try:
            mst = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"))
            out["must_staple"] = bool(mst)
        except x509.ExtensionNotFound:
            pass
        pk = cert.public_key()
        out["key_alg"] = type(pk).__name__
        if isinstance(pk, rsa.RSAPublicKey):
            out["key_bits"] = pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            out["key_bits"] = pk.curve.key_size
        out["sig_alg"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:  # noqa: BLE001
        pass
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        return [Finding(severity="info", title="Crypto-agility skipped (no host)",
                        evidence="", remediation="No action.", url=ctx["target"])]

    step("crypto: TLS handshake...")
    tls = await asyncio.to_thread(_gather_tls, host)
    if not tls:
        return [Finding(severity="low", title="Crypto-agility: TLS handshake failed",
                         evidence=f"host={host}", remediation="Investigate connectivity.",
                         url=ctx["target"])]

    # ---- #47, #48 PQ + TLS 1.3 ----
    if tls["tls_version"] != "TLSv1.3":
        findings.append(Finding(
            severity="medium",
            title=f"TLS version is {tls['tls_version']}, not TLS 1.3",
            evidence=f"Negotiated: {tls['tls_version']}",
            remediation="Enable TLS 1.3. Required for post-quantum hybrid KEX.",
            url=ctx["target"],
        ))

    # OpenSSL exposes PQ group via `cipher` name only on newer builds. We
    # can only confirm absence here; for full PQ-readiness check, run
    # `openssl s_client -groups X25519MLKEM768 -connect host:443` manually.
    findings.append(Finding(
        severity="info",
        title="Post-quantum KEX support — manual confirmation needed",
        evidence=(f"Python stdlib ssl can't introspect the group. Test with:\n"
                  f"  openssl s_client -tls1_3 -groups X25519MLKEM768 -connect {host}:443"),
        remediation=("Cloudflare / Google enable X25519MLKEM768 by default. If self-hosting nginx, "
                     "upgrade to OpenSSL 3.5+ and add `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;`."),
        url=ctx["target"],
    ))

    # ---- #49, #50 cert inventory + RSA size ----
    cert = _parse_cert(tls["cert_der"])
    findings.append(Finding(
        severity="info",
        title="Crypto inventory",
        evidence=(f"subject={cert['subject'][:80]}\n"
                  f"sans={len(cert['sans'])} (first 3: {', '.join(cert['sans'][:3])})\n"
                  f"key={cert['key_alg']} {cert['key_bits']} bits\n"
                  f"sig={cert['sig_alg']}\n"
                  f"must-staple={cert['must_staple']}"),
        remediation="No action.",
        url=ctx["target"],
    ))
    if "RSA" in cert["key_alg"] and cert["key_bits"] and cert["key_bits"] < 2048:
        findings.append(Finding(
            severity="high",
            title=f"RSA cert key size only {cert['key_bits']} bits",
            evidence=f"key_bits={cert['key_bits']}",
            remediation="Reissue cert with RSA >=2048 (ideally 3072) or ECDSA P-256/P-384. Sub-2048 RSA is below NIST baseline since 2013.",
            url=ctx["target"],
        ))

    # ---- #51 curve preference (informational) ----
    findings.append(Finding(
        severity="info",
        title="Curve preference — best assessed via test endpoint",
        evidence=f"Use https://www.ssllabs.com/ssltest/analyze.html?d={host} to see the offered curves and the server's preference order.",
        remediation="Prefer X25519 + P-256 + P-384. Disable P-192 (legacy).",
        url=f"https://www.ssllabs.com/ssltest/analyze.html?d={host}",
    ))

    return findings
