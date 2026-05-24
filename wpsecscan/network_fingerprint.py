"""Round-62 #B27 — JA3 / JA4 TLS fingerprint of the target.

Both fingerprints capture the TLS ClientHello (JA3 = openssl ciphers +
extensions hash; JA4 = newer Cisco format). Useful for:
  - identifying the OS/browser/library a connecting client uses
  - WAF rule fingerprinting (does the WAF intercept and downgrade
    the TLS handshake?)
  - bot-detection bypass research

The Python stdlib `ssl` module exposes negotiated cipher + version but
not the raw ClientHello. We do a best-effort:
  - Establish a TLS conn to host:443
  - Record negotiated cipher, version, named-group, ALPN
  - Compute a lightweight JA3-style fingerprint from what's available

For full JA3 + JA4 you'd need raw TLS parsing (mitmproxy / scapy / a
manual ClientHello builder). This module ships a stub that produces a
*partial* JA3 — enough for cross-scan comparison + WAF identification —
without pulling heavy deps.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from urllib.parse import urlparse


def gather(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Return {tls_version, cipher, alpn, named_group, ja3_lite, ja4_lite}."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher() or ("", "", 0)
                version = ssock.version() or ""
                alpn = ssock.selected_alpn_protocol() or ""
                shared = ssock.shared_ciphers() or []
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError) as e:
        return {"error": f"{type(e).__name__}: {e}"}

    # Lightweight JA3: hash(version + negotiated cipher + ALPN + shared cipher names)
    seed = ";".join([
        version,
        cipher[0] if cipher else "",
        alpn,
        ",".join(sorted({c[0] for c in shared if c})[:20]),
    ])
    ja3_lite = hashlib.md5(seed.encode("utf-8")).hexdigest()
    ja4_lite = "t" + (version.replace("TLSv", "").replace(".", "") or "00") + "_" + ja3_lite[:12]

    return {
        "tls_version":   version,
        "cipher":        cipher[0] if cipher else "",
        "alpn":          alpn,
        "shared_count":  len(shared),
        "ja3_lite":      ja3_lite,
        "ja4_lite":      ja4_lite,
    }


def fingerprint_url(url: str) -> dict:
    """Convenience wrapper — accepts a URL, splits to host:port, returns gather()."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host or port != 443:
        return {"error": "https only"}
    return gather(host, port)
