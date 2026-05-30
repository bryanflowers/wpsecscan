"""Deep TLS audit — one handshake, all the checks.

Covers everything beyond the basic version-and-expiry that `tls_headers` does:
  - Weak protocol acceptance (TLSv1, TLSv1.1, SSLv3, SSLv2 → PCI-DSS bans)
  - Weak cipher tokens (RC4, 3DES, NULL, EXPORT, MD5, anon)
  - Negotiated cipher AEAD / forward-secrecy
  - Self-signed indicators (subject == issuer)
  - SubjectAltName list coverage
  - Certificate expiry tiering (expired → critical; <14d → high; <30d → medium)
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


# B18 (v2.8.0) — locale-independent X.509 cert-date parser.
# `datetime.strptime("Jan 24 ...", "%b ...")` works only when the
# running process locale is English. On Turkish, German, Japanese
# servers the parse silently failed. Hardcoded English month map
# matches X.509 cert NOT-AFTER format (RFC 5280 specifies
# UTCTime / GeneralizedTime, but OpenSSL renders as English).
_X509_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _parse_cert_date_en(not_after: str) -> "datetime | None":
    """Parse OpenSSL-style cert dates like `Jan 24 12:34:56 2026 GMT`
    using a locale-independent English month map. Returns None on
    any parse error."""
    parts = (not_after or "").strip().split()
    if len(parts) < 4:
        return None
    try:
        mon = _X509_MONTHS.get(parts[0][:3].lower())
        if mon is None:
            return None
        day = int(parts[1])
        h, m, s = (int(p) for p in parts[2].split(":"))
        year = int(parts[3])
        return datetime(year, mon, day, h, m, s, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _connect_with(host: str, port: int, protocol_name: str) -> tuple[bool, str]:
    """Try to negotiate the given protocol against host:port."""
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


def _inspect(host: str, port: int = 443) -> dict:
    """Single handshake; collect cert chain, cipher, expiry, SAN list."""
    out = {
        "tls_version": None, "cipher": None, "cipher_bits": None,
        "subject_cn": None, "issuer_cn": None, "expires_in_days": None,
        "not_after": None,
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
                san = cert.get("subjectAltName", ())
                if san:
                    sans = [v for (_t, v) in san if isinstance(v, str)]
                    out["san_count"] = len(sans)
                    out["san_sample"] = sans[:5]
                not_after = cert.get("notAfter")
                if not_after:
                    out["not_after"] = not_after
                    # B18 (v2.8.0) — `strptime("%b %d ...")` is locale-
                    # dependent on Windows + glibc. On a Turkish-locale
                    # host January = "Oca", so parsing silently failed
                    # and `expires_in_days` went missing from every
                    # finding. Use a fixed English-month map instead.
                    try:
                        dt = _parse_cert_date_en(not_after)
                        if dt is not None:
                            out["expires_in_days"] = (dt - datetime.now(timezone.utc)).days
                    except ValueError:
                        pass
                if out["subject_cn"] and out["subject_cn"] == out["issuer_cn"]:
                    out["is_self_signed"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    target = ctx["target"]
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or 443

    if parsed.scheme != "https" or not host:
        findings.append(Finding(
            severity="info",
            title="Deep TLS audit skipped — site is not HTTPS",
            evidence=f"target scheme: {parsed.scheme}",
            remediation="Serve the site over HTTPS first; then this check becomes meaningful.",
            url=target,
        ))
        return findings

    step(f"deep TLS handshake to {host}:{port}...")
    info = await asyncio.to_thread(_inspect, host, port)
    if info["error"]:
        findings.append(Finding(
            severity="medium",
            title="Deep TLS handshake failed",
            evidence=f"Connect/handshake to {host}:{port} failed: {info['error']}",
            remediation="Verify the cert chain is valid and SNI works.",
            url=target,
        ))
        return findings

    # 1. Weak-protocol acceptance (TLSv1 / TLSv1.1)
    rejected_weak: list[str] = []
    for proto in WEAK_PROTOCOLS:
        step(f"testing weak TLS protocol {proto}...")
        ok, msg = await asyncio.to_thread(_connect_with, host, port, proto)
        if ok:
            findings.append(Finding(
                severity="high",
                title=f"Weak TLS protocol accepted: {proto}",
                evidence=f"{host}:{port} {msg}\nWeak protocols banned by PCI-DSS 3.2.1 and most modern compliance regimes.",
                remediation=(
                    f"Disable {proto} at the web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`  "
                    f"Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`. If behind a CDN, configure at the CDN edge."
                ),
                url=target,
            ))
        else:
            rejected_weak.append(proto)

    # 2. Cipher quality
    cipher_name = info["cipher"] or ""
    if cipher_name:
        if any(tok in cipher_name for tok in WEAK_CIPHER_TOKENS):
            findings.append(Finding(
                severity="high",
                title=f"Weak TLS cipher in use: {cipher_name}",
                evidence=f"Negotiated cipher: {cipher_name} ({info['cipher_bits']} bits)",
                remediation=(
                    "Update the cipher suite. nginx: `ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:...`. "
                    "See Mozilla SSL Configuration Generator (intermediate or modern profile)."
                ),
                url=target,
            ))
        else:
            is_aead = any(s in cipher_name.upper() for s in ("GCM", "POLY1305", "CCM"))
            sev = "info" if is_aead else "medium"
            title = ("Modern AEAD cipher in use" if is_aead
                     else "Non-AEAD cipher in use (consider CHACHA20-POLY1305 / GCM)")
            findings.append(Finding(
                severity=sev,
                title=title,
                evidence=(
                    f"Negotiated TLS: {info['tls_version']}\n"
                    f"Cipher:         {cipher_name}\n"
                    f"Cipher bits:    {info['cipher_bits']}\n"
                ),
                remediation=(
                    "Prefer AEAD ciphers (AES-GCM, CHACHA20-POLY1305). Nginx example:\n"
                    "  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
                    "  ssl_prefer_server_ciphers on;"
                ),
                url=target,
            ))

    # 3. Self-signed
    if info["is_self_signed"]:
        findings.append(Finding(
            severity="high",
            title=f"Self-signed certificate at {host}",
            evidence=f"Subject CN = Issuer CN = {info['subject_cn']!r}. No trusted CA in the chain.",
            remediation="Issue a real cert from Let's Encrypt (`certbot`) or your provider. Self-signed certs train users to dismiss browser warnings.",
            url=target,
        ))

    # 4. SAN coverage
    if info["san_count"] == 0:
        findings.append(Finding(
            severity="low",
            title="Certificate has no SubjectAltName (SAN) — modern browsers will reject",
            evidence=f"Subject CN: {info['subject_cn']}, no SAN.",
            remediation="Reissue the certificate with a SAN list including every host you serve.",
            url=target,
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"Certificate covers {info['san_count']} SAN entries",
            evidence=f"Sample SANs: {', '.join(info['san_sample'])}",
            remediation="No action needed.",
            url=target,
        ))

    # 5. Certificate expiry tiering (single finding per band)
    days = info["expires_in_days"]
    not_after = info["not_after"] or "unknown"
    if days is not None:
        if days <= 0:
            findings.append(Finding(
                severity="critical",
                title=f"TLS certificate EXPIRED {abs(days)} days ago",
                evidence=f"notAfter: {not_after}",
                remediation="Renew immediately. If using Let's Encrypt, check certbot/renewal cron.",
                url=target,
            ))
        elif days <= 14:
            findings.append(Finding(
                severity="high",
                title=f"TLS certificate expires in {days} days",
                evidence=f"notAfter: {not_after}; Subject CN: {info['subject_cn']}",
                remediation="Renew NOW. Verify auto-renew is configured. `certbot renew --dry-run`.",
                url=target,
            ))
        elif days <= 30:
            findings.append(Finding(
                severity="medium",
                title=f"TLS certificate expires in {days} days",
                evidence=f"notAfter: {not_after}; Subject CN: {info['subject_cn']}",
                remediation="Verify renewal is automated. Set a calendar reminder if not.",
                url=target,
            ))

    return findings
