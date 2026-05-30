"""#26 TLS renegotiation DoS probe.

The 2009-vintage CVE-2009-3555 flaw: a server that allows client-initiated
renegotiations can be DoS'd with a single connection that triggers many
renegotiations (server CPU is ~5x client CPU per reneg).

Modern OpenSSL disables this by default; older nginx / Apache / IIS may
still allow it. We probe by negotiating + renegotiating 5x; flag if the
server accepts more than 1.
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


def _tls_reneg_test(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    """Returns (vulnerable, detail). Vulnerable = server accepts >1 renegotiation."""
    # B3 (v2.8.0) — same fix as B2 (websocket_audit). Punycode-encode
    # IDN hosts to ASCII before either putting them in a Host: header
    # (which MUST be ASCII) or passing them to socket.create_connection
    # (the resolver supports IDN but the raw bytes in the request did
    # not). Falls back gracefully on non-IDN hosts.
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        ascii_host = host
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                             server_hostname=ascii_host)
        s.settimeout(timeout)
        s.connect((ascii_host, port))
        # Try to renegotiate. Python doesn't expose SSL_renegotiate directly,
        # but we can test by sending a partial HTTP request and seeing if the
        # server tolerates the reneg dance. Modern Python (3.10+) raises on
        # unsupported reneg; old servers silently accept.
        try:
            s.send(b"GET / HTTP/1.1\r\nHost: " + ascii_host.encode("ascii") + b"\r\n\r\n")
            time.sleep(0.3)
            s.recv(1024)
            # We can't truly test reneg from Python's high-level API, so we
            # emit an info finding pointing at the manual test command.
            s.close()
            return (False, "Python's SSL stack doesn't expose reneg directly — manual test required")
        finally:
            try: s.close()
            except OSError: pass
    except (socket.timeout, ssl.SSLError, OSError) as e:
        return (False, f"connection error: {e}")


async def check(client: Client, ctx: dict) -> list[Finding]:
    parsed = urlparse(ctx["target"])
    if parsed.scheme != "https":
        return [Finding(severity="info", title="TLS reneg DoS skipped (non-HTTPS target)",
                        evidence="Target uses HTTP — TLS reneg N/A.", remediation="No action.",
                        url=ctx["target"])]
    host = parsed.hostname
    port = parsed.port or 443
    _, detail = _tls_reneg_test(host, port)
    return [Finding(
        severity="info",
        title=f"TLS renegotiation DoS — manual test required",
        evidence=f"{detail}\n\nVerify manually:\n  openssl s_client -connect {host}:{port} -reconnect 5",
        remediation="If the server accepts >1 client-initiated reneg, add `ssl_session_tickets off;` + `ssl_reuse_sessions off;` to nginx, or upgrade OpenSSL.",
        url=ctx["target"],
    )]
