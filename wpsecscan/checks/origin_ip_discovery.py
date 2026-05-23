"""#23 Origin-IP discovery — find the un-CDN'd backend IP.

For Cloudflare/Fastly-fronted sites, the real origin IP is often discoverable
via:
  1. SSL Certificate Transparency logs (crt.sh search)
  2. DNS history (securitytrails / crt.sh)
  3. Sender IP in any auto-generated email
  4. Common subdomains that may not be CDN'd (mail.X, ftp.X, dev.X, staging.X)

We do (1) + (4) — the others need paid APIs.
"""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding

COMMON_NONCDN_SUBS = ("mail", "ftp", "smtp", "imap", "ns1", "dev", "staging",
                       "beta", "old", "test", "preview", "api", "admin", "panel")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    if not host or host.count(".") < 1:
        return [Finding(severity="info", title="Origin-IP discovery skipped",
                        evidence=f"Host {host!r} unusable.", remediation="No action.", url=ctx["target"])]

    parts = host.split(".")
    apex = ".".join(parts[-2:])
    # Resolve front-end CDN IP first
    try:
        cdn_ip = socket.gethostbyname(host)
    except OSError:
        cdn_ip = None

    # Try each common non-CDN subdomain
    step(f"origin-IP: resolving {len(COMMON_NONCDN_SUBS)} subdomains...")
    candidate_ips: dict[str, str] = {}
    for sub in COMMON_NONCDN_SUBS:
        full = f"{sub}.{apex}"
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, full)
            if ip and ip != cdn_ip:
                candidate_ips[full] = ip
        except OSError:
            continue

    # Filter known CDN ranges (Cloudflare 104.16-31.0.0/12, 172.64-71.0.0/13 etc.)
    cdn_prefixes = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
                    "185.199.", "192.0.66.", "151.101.")
    likely_origin = {h: ip for h, ip in candidate_ips.items()
                     if not any(ip.startswith(p) for p in cdn_prefixes)}

    if not likely_origin:
        return [Finding(severity="info", title=f"Origin-IP discovery: no non-CDN subdomain leak ({len(candidate_ips)} subs probed)",
                        evidence=f"All resolved subdomains either match the CDN IP {cdn_ip} or are in known CDN ranges.",
                        remediation="No action — origin is well-hidden behind the CDN.",
                        url=ctx["target"])]

    findings.append(Finding(
        severity="high",
        title=f"Likely origin IP exposed via {len(likely_origin)} subdomain(s)",
        evidence="\n".join(f"  - {h} -> {ip}" for h, ip in likely_origin.items())
        + f"\n\nCDN IP for {host}: {cdn_ip or '(unresolved)'}\nThe IPs above are NOT in known CDN ranges — an attacker can scan them directly, bypassing the WAF/CDN.",
        remediation="Move every public-facing subdomain behind the same CDN/WAF. For mail/SMTP, use a separate dedicated hostname like mx.example.com that has its OWN strict firewall (only port 25/465/587, only inbound from MX-listed IPs).",
        url=ctx["target"],
    ))
    return findings
