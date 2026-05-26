"""Items #21 + #22 — modern TLS feature audit.

#21 — TLS 1.3 0-RTT (Early-Data). 0-RTT allows the client to send
     application data on the FIRST flight, before the handshake
     completes. The server cannot tell whether the data is being
     replayed by an on-path attacker — a real risk for state-changing
     POST requests. WP admin endpoints reachable via 0-RTT are a
     replay-attack vector.

#22 — OCSP stapling + must-staple. Stapling lets the server proactively
     prove cert non-revocation in the handshake; must-staple makes
     clients require it. Without stapling, browsers must do a fallback
     OCSP query, leaking the visitor's IP to the CA and slowing the
     connection.

Implementation: shells out to `openssl s_client` when available
(every modern OS has it). Falls back to a single Python `ssl`
handshake when not — in that case 0-RTT detection is skipped (it's
not exposed at the Python ssl level) and we only report whether the
server negotiates TLS 1.3 successfully.
"""
from __future__ import annotations

import asyncio
import shutil
import socket
import ssl
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    target = ctx["target"]
    u = urlparse(target)
    host = u.hostname
    port = u.port or (443 if u.scheme in ("https", "") else 80)
    if not host or u.scheme != "https":
        return [Finding(
            severity="info",
            title="TLS modern-feature audit skipped (non-HTTPS target)",
            evidence=f"target: {target}",
            remediation="No action.",
            url=target,
        )]

    if shutil.which("openssl"):
        step(f"running openssl s_client -status against {host}:{port}...")
        findings.extend(await _openssl_probe(host, port, target))
    else:
        step("openssl not on PATH; falling back to ssl-stdlib handshake...")
        findings.extend(_ssl_handshake_probe(host, port, target))

    return findings or [Finding(
        severity="info",
        title="TLS modern-feature audit completed without findings",
        evidence=f"Probed {host}:{port}.",
        remediation="No action needed.",
        url=target,
    )]


async def _openssl_probe(host: str, port: int, target: str) -> list[Finding]:
    """Run two openssl invocations: one with -status (OCSP), one with -tls1_3."""
    findings: list[Finding] = []

    # 1) OCSP stapling probe
    proc = await asyncio.create_subprocess_exec(
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-status", "-brief",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=b"Q\n"), timeout=10.0)
    except asyncio.TimeoutError:
        proc.kill()
        return [Finding(
            severity="info",
            title="TLS audit — openssl s_client timed out",
            evidence=f"openssl s_client {host}:{port} did not return within 10s.",
            remediation="No action.",
            url=target,
        )]
    text = (out + err).decode("utf-8", errors="replace")

    if "OCSP response: no response sent" in text:
        findings.append(Finding(
            severity="low",
            title=f"OCSP stapling NOT enabled on {host}",
            evidence=(
                "openssl s_client -status reported `OCSP response: no response "
                "sent`. Visitors will fall back to direct OCSP queries to the "
                "CA — slower connections + visitor-IP leakage to the CA."
            ),
            remediation=(
                "Enable OCSP stapling at the web server:\n"
                "  • nginx: `ssl_stapling on; ssl_stapling_verify on;` + a "
                "valid `resolver` directive.\n"
                "  • Apache: `SSLUseStapling on` + `SSLStaplingCache` directive.\n"
                "  • Cloudflare-fronted sites get stapling automatically; verify "
                "you're not unproxying the origin."
            ),
            url=target,
        ))
    elif "OCSP Response Status: successful" in text:
        findings.append(Finding(
            severity="info",
            title=f"OCSP stapling enabled on {host}",
            evidence="openssl s_client -status returned a stapled OCSP response.",
            remediation="No action needed.",
            url=target,
        ))

    # Must-staple is a cert extension; openssl prints it in the cert dump under
    # X509v3 TLS Feature: status_request. Detect via a separate invocation
    # (-brief mode hides the cert).
    proc2 = await asyncio.create_subprocess_exec(
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-showcerts",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out2, _ = await asyncio.wait_for(proc2.communicate(input=b"Q\n"), timeout=10.0)
    except asyncio.TimeoutError:
        proc2.kill()
        out2 = b""
    cert_text = out2.decode("utf-8", errors="replace")
    # The TLS Feature extension OID 1.3.6.1.5.5.7.1.24 with value status_request.
    if "TLS Feature" in cert_text and "status_request" in cert_text.lower():
        findings.append(Finding(
            severity="info",
            title=f"TLS must-staple extension present on {host}",
            evidence="Certificate carries the TLS Feature: status_request extension (must-staple).",
            remediation="No action needed.",
            url=target,
        ))

    # 2) 0-RTT / Early Data probe — openssl s_client supports -early_data
    # but only when the server has issued a previous session ticket. The
    # accurate test is two-step: first connect & save a session, then
    # connect using -sess_in and -early_data.
    # For a passive read we just check whether the server advertises
    # max_early_data_size in the encrypted-extensions on the TLS 1.3
    # handshake. openssl exposes this via "Max Early Data: <N>" when run
    # with -tls1_3 -trace.
    proc3 = await asyncio.create_subprocess_exec(
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-tls1_3", "-msg",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out3, _ = await asyncio.wait_for(proc3.communicate(input=b"Q\n"), timeout=10.0)
    except asyncio.TimeoutError:
        proc3.kill()
        out3 = b""
    trace = out3.decode("utf-8", errors="replace")
    # `early_data(42)` in the ServerHello extensions block ⇒ 0-RTT enabled.
    if "early_data" in trace:
        findings.append(Finding(
            severity="medium",
            title=f"TLS 1.3 0-RTT (Early Data) enabled on {host}",
            evidence=(
                "Server's TLS 1.3 handshake advertises the `early_data` "
                "extension. Clients can send application data on the FIRST "
                "flight before the handshake completes. An on-path attacker "
                "can REPLAY captured 0-RTT data — a real concern for "
                "state-changing endpoints (POST /wp-admin/admin-ajax.php, "
                "wp-login, REST mutations)."
            ),
            remediation=(
                "Disable 0-RTT at the web server unless every state-changing "
                "endpoint is genuinely idempotent. Nginx: `ssl_early_data off;` "
                "(default). Cloudflare: Dashboard → SSL/TLS → Edge Certificates "
                "→ 0-RTT Connection Resumption → Off.\n"
                "If you need 0-RTT for performance, add anti-replay caches "
                "on the application side (e.g. nonce-bound CSRF tokens that "
                "can only be used once)."
            ),
            url=target,
        ))

    return findings


def _ssl_handshake_probe(host: str, port: int, target: str) -> list[Finding]:
    """Fallback when openssl isn't on PATH. We can only confirm TLS 1.3
    negotiates; 0-RTT and OCSP stapling are not exposed at the Python
    ssl-module level (the C `OCSP_RESPONSE` is, but only via private APIs)."""
    findings: list[Finding] = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except (ssl.SSLError, ValueError):
        return findings
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                findings.append(Finding(
                    severity="info",
                    title=f"TLS 1.3 negotiated on {host} (openssl unavailable for deeper probe)",
                    evidence=(
                        f"Negotiated {ver}. OCSP stapling + 0-RTT detection "
                        "require the openssl s_client binary, which was not "
                        "found on PATH on the scanner host."
                    ),
                    remediation=(
                        "For a deeper handshake audit install OpenSSL on the "
                        "scanner host. Alternatively use a public scanner like "
                        "https://www.ssllabs.com/ssltest/ to verify OCSP "
                        "stapling, must-staple, and 0-RTT."
                    ),
                    url=target,
                ))
    except (ssl.SSLError, socket.timeout, OSError):
        pass
    return findings
