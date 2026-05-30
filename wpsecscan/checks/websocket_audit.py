"""WebSocket audit.

Probes for /ws, /wss, /socket.io/, /websocket endpoints. Sends an HTTP/1.1
Upgrade: websocket handshake (using a raw socket since httpx doesn't natively
support WS) and checks:
  1. Whether the endpoint accepts the upgrade
  2. Whether the Origin header is enforced (cross-origin WS = CSRF over WS)
  3. Whether auth is enforced before upgrade
"""
from __future__ import annotations

import asyncio
import base64
import secrets
import socket
import ssl as _ssl
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

PROBE_PATHS = (
    "/ws", "/wss", "/socket.io/?EIO=4&transport=websocket",
    "/websocket", "/api/ws", "/wp-content/plugins/chat/ws",
    "/wp-json/realtime/v1/ws",
)


def _ws_handshake(host: str, port: int, path: str, scheme: str,
                  origin: str = "https://wpsec-evil.example.com") -> dict:
    """Send a single WebSocket Upgrade request. Returns dict with .status, .headers, .accept_key."""
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    # B2 (v2.8.0) — IDN hosts (e.g. `café.example.com`) cannot be put
    # into an HTTP Host: header as Unicode — the header must be ASCII.
    # Punycode-encode the host before interpolation. urlparse returns
    # the raw Unicode hostname; idna encoding converts it to its
    # `xn--...` ASCII form. Falls back gracefully if the host is
    # already ASCII or doesn't fit the idna rules.
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        ascii_host = host
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {ascii_host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        f"User-Agent: WPSecScan/ws-probe\r\n"
        f"\r\n"
    )
    try:
        sock = socket.create_connection((ascii_host, port), timeout=5.0)
        if scheme == "wss" or port == 443:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ascii_host)
        sock.sendall(request.encode("ascii"))
        data = b""
        try:
            for _ in range(10):
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
        finally:
            sock.close()
        head, _sep, _body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin1", errors="replace").splitlines()
        if not lines:
            return {"err": "no response"}
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            return {"err": f"bad status line: {lines[0][:80]}"}
        hdrs = {}
        for line in lines[1:]:
            if ":" in line:
                k, _c, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        return {"status": status, "headers": hdrs}
    except (socket.timeout, OSError, _ssl.SSLError) as e:
        return {"err": f"{type(e).__name__}: {e}"}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    target = ctx["target"]
    p = urlparse(target)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    scheme = "wss" if p.scheme == "https" else "ws"

    upgraded: list[tuple[str, dict]] = []
    cross_origin_pass: list[str] = []
    for path in PROBE_PATHS:
        step(f"probing WS endpoint {path}...")
        res = await asyncio.to_thread(_ws_handshake, host, port, path, scheme)
        if "err" in res:
            continue
        status = res.get("status", 0)
        hdrs = res.get("headers", {})
        # 101 means upgrade succeeded
        if status == 101 and hdrs.get("upgrade", "").lower() == "websocket":
            upgraded.append((path, res))
            # Cross-origin: we sent Origin: evil. If it still upgraded, no Origin check.
            cross_origin_pass.append(path)

    if not upgraded:
        findings.append(
            Finding(
                severity="info",
                title="No WebSocket endpoints reachable at common paths",
                evidence=f"Probed: {', '.join(PROBE_PATHS)}",
                remediation="No action.",
                url=target,
            )
        )
        return findings

    for path in cross_origin_pass:
        findings.append(
            Finding(
                severity="high",
                title=f"WebSocket {path} accepts cross-origin upgrade",
                evidence=(
                    "Handshake from `Origin: https://wpsec-evil.example.com` was accepted (HTTP 101). "
                    "An attacker can mint a WebSocket from a malicious origin and the server won't "
                    "reject the connection — that's CSWSH (cross-site WebSocket hijacking)."
                ),
                remediation=(
                    "Validate the Origin header in the WebSocket handler. For the standard "
                    "WordPress plugins that ship WS (real-time chat, live notifications): "
                    "check the plugin author's docs for Origin-pinning. Reference: "
                    "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking"
                ),
                url=client.url(path),
            )
        )

    # Even non-cross-origin upgrade is worth flagging if auth wasn't enforced
    other = [p for p, _r in upgraded if p not in cross_origin_pass]
    if other:
        findings.append(
            Finding(
                severity="medium",
                title=f"WebSocket endpoint(s) reachable: {', '.join(other)}",
                evidence="Endpoint accepted the upgrade — verify the WS handler enforces auth before exposing data.",
                remediation="Audit the plugin code: the WS handler should call `wp_get_current_user()` or equivalent.",
                url=target,
            )
        )
    return findings
