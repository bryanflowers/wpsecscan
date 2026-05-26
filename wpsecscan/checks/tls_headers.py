from __future__ import annotations

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

REQUIRED_HEADERS = {
    "strict-transport-security": (
        "high",
        "Add HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. "
        "Without it, the very first request to your domain can be downgraded to HTTP.",
    ),
    "content-security-policy": (
        "medium",
        "Add a Content-Security-Policy. Start with a report-only policy to map your asset hosts, "
        "then enforce. Even a permissive `default-src 'self' https:; object-src 'none'` blocks the most common XSS payloads.",
    ),
    "x-frame-options": (
        "medium",
        "Add `X-Frame-Options: SAMEORIGIN` (or a CSP frame-ancestors directive) to prevent clickjacking.",
    ),
    "x-content-type-options": (
        "low",
        "Add `X-Content-Type-Options: nosniff` to stop MIME sniffing.",
    ),
    "referrer-policy": (
        "low",
        "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    "permissions-policy": (
        "low",
        "Add a `Permissions-Policy` header to disable powerful APIs (camera, microphone, geolocation, etc.) for any features you don't use.",
    ),
}


def _check_tls(host: str, port: int = 443) -> tuple[str | None, str | None, int | None]:
    """Returns (tls_version, cert_subject, days_until_expiry)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                exp = cert.get("notAfter")
                days = None
                if exp:
                    dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (dt - datetime.now(timezone.utc)).days
                return version, cn, days
    except Exception:  # noqa: BLE001
        return None, None, None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    # Headers via real GET (some sites return different headers to HEAD)
    step("fetching / for security-header inspection...")
    r = await client.get("/")
    if r is None:
        findings.append(
            Finding(
                severity="medium",
                title="Could not fetch / for header inspection",
                evidence="GET / returned no response (timeout or transport error).",
                remediation="Verify the site is reachable and re-run.",
                url=ctx["target"],
            )
        )
        return findings

    hdrs = {k.lower(): v for k, v in r.headers.items()}
    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")

    for header, (sev, fix) in REQUIRED_HEADERS.items():
        if header not in hdrs:
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Missing security header: {header}",
                    evidence=f"GET / response did not include {header}.",
                    remediation=fix,
                    url=ctx["target"],
                )
            )

    if server or powered:
        bits = [b for b in (f"Server: {server}" if server else None, f"X-Powered-By: {powered}" if powered else None) if b]
        # CDN-injected Server headers (Cloudflare, Vercel, Fly) can't be
        # suppressed at origin — the site owner has no remedy, so don't fire
        # a finding that points at /etc/nginx. Downgrade to info instead.
        server_lower = (server or "").lower()
        powered_lower = (powered or "").lower()
        cdn_injected = any(tok in server_lower or tok in powered_lower
                           for tok in ("cloudflare", "vercel", "fly.io", "netlify", "akamai", "fastly"))
        # Also suppress when the WAF check already detected a known CDN/WAF.
        waf_shared = ctx.get("shared", {}).get("waf") or []
        if cdn_injected or waf_shared:
            findings.append(
                Finding(
                    severity="info",
                    title="Server header set by upstream CDN (cannot be suppressed at origin)",
                    evidence="; ".join(bits) + (f"\nDetected CDN/WAF: {', '.join(waf_shared)}" if waf_shared else ""),
                    remediation=(
                        "No action: this header is injected by your CDN/edge, not your web "
                        "server. Hide it via the CDN's transform/response-header rules if "
                        "you still want it suppressed."
                    ),
                    url=ctx["target"],
                )
            )
        else:
            findings.append(
                Finding(
                    severity="low",
                    title="Server / X-Powered-By headers leak software info",
                    evidence="; ".join(bits),
                    remediation=(
                        "Suppress these headers. Nginx: `more_clear_headers Server X-Powered-By;` (headers-more module) "
                        "or `server_tokens off;`. PHP: set `expose_php = Off` in php.ini."
                    ),
                    url=ctx["target"],
                )
            )

    if is_https and host:
        step(f"performing TLS handshake to {host}:443...")
        tls_ver, cn, days = await asyncio.to_thread(_check_tls, host)
        if tls_ver:
            if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(
                    Finding(
                        severity="high",
                        title=f"Outdated TLS version supported: {tls_ver}",
                        evidence=f"Connection to {host}:443 negotiated {tls_ver}.",
                        remediation="Disable TLS < 1.2 in your web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`.",
                        url=ctx["target"],
                    )
                )
            if days is not None:
                if days < 0:
                    findings.append(
                        Finding(
                            severity="critical",
                            title="TLS certificate has expired",
                            evidence=f"Cert CN={cn}; expired {-days} day(s) ago.",
                            remediation="Renew the certificate immediately (Let's Encrypt: `certbot renew`).",
                            url=ctx["target"],
                        )
                    )
                elif days < 14:
                    findings.append(
                        Finding(
                            severity="high",
                            title=f"TLS certificate expires soon ({days} day(s))",
                            evidence=f"Cert CN={cn}; expires in {days} day(s).",
                            remediation="Renew now; check that auto-renewal is configured and the renew hook reloads the web server.",
                            url=ctx["target"],
                        )
                    )
        else:
            findings.append(
                Finding(
                    severity="medium",
                    title="Could not complete TLS handshake for inspection",
                    evidence=f"Socket-level handshake to {host}:443 failed.",
                    remediation="Verify the cert chain is complete and the server presents a valid SNI cert.",
                    url=ctx["target"],
                )
            )
    elif not is_https:
        findings.append(
            Finding(
                severity="high",
                title="Site is being scanned over plain HTTP",
                evidence=f"Target URL is {ctx['target']} (no TLS).",
                remediation="Serve the site over HTTPS only. Get a free cert via Let's Encrypt and redirect HTTP→HTTPS at the server.",
                url=ctx["target"],
            )
        )

    return findings
