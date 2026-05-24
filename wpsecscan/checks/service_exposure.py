"""Round-62 #B35-B37 — service-port exposure (Redis / Memcache / Elasticsearch /
DB ports) on the WP-host's IP.

Defensive intent: many WP hosts run Redis / Memcache / Elasticsearch for
caching / search on the SAME server as Apache+PHP. If the bind address
is 0.0.0.0 (not 127.0.0.1), those ports are reachable from the public
internet — catastrophic.

We don't run a port scan from the scanner host (network-noisy, often
breaks the user's own egress rules). Instead we:
  - resolve the target hostname
  - try a single 1-second TCP connect to each suspect port
  - if it opens, that's evidence the port is publicly bound
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


def _is_private_or_local(host: str) -> bool:
    """True for RFC1918 / loopback / link-local IPs or `localhost`-style hostnames."""
    if host in ("localhost", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
             or ip.is_multicast or ip.is_reserved)


# (port, label, advice)
SERVICES = [
    (3306,  "MySQL / MariaDB", "Bind to 127.0.0.1 only. If remote DB access is needed, restrict via firewall + SSL."),
    (5432,  "PostgreSQL",      "Bind to 127.0.0.1 only. listen_addresses = 'localhost' in postgresql.conf."),
    (27017, "MongoDB",         "Bind to 127.0.0.1; require auth (--auth); enable TLS."),
    (6379,  "Redis",           "Bind to 127.0.0.1; require AUTH password; bind 127.0.0.1 in redis.conf."),
    (11211, "Memcache",        "Bind to 127.0.0.1 (-l 127.0.0.1). Memcache has NO auth — public bind = full RCE via SASL CVEs."),
    (9200,  "Elasticsearch HTTP", "Bind to 127.0.0.1; enable X-Pack / xpack.security.enabled=true."),
    (9300,  "Elasticsearch transport", "Bind to 127.0.0.1; never expose to public internet."),
    (5601,  "Kibana",          "Behind nginx/Cloudflare with Basic auth or OAuth proxy."),
    (8983,  "Solr",            "Bind to 127.0.0.1; require auth."),
    (25,    "SMTP",            "If exposed, enforce TLS + STARTTLS + AUTH."),
    (139,   "NetBIOS",         "Block at firewall — should never be public."),
    (445,   "SMB",             "Block at firewall — should never be public."),
    (3389,  "RDP",             "Behind VPN / bastion — never directly public."),
    (5900,  "VNC",             "Behind VPN / bastion — never directly public."),
]


async def _try_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=timeout).close()),
            timeout=timeout + 0.5,
        )
        return True
    except (socket.timeout, socket.gaierror, ConnectionRefusedError,
             OSError, asyncio.TimeoutError):
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    host = urlparse(ctx["target"]).hostname or ""
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        return [Finding(severity="info", title="Service-port exposure — skipped for local target",
                        evidence=f"host={host}", remediation="No action.", url=ctx["target"])]

    # Resolve hostname → IP for the RFC1918 check
    resolved_ip = host
    try:
        if not host.replace(".", "").isdigit():
            resolved_ip = socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        pass

    # Skip private / RFC1918 / link-local — these would fire on any LAN target
    # and the findings would be informational at best. Override with env var.
    if _is_private_or_local(resolved_ip) and not os.environ.get("WPSECSCAN_SCAN_LAN"):
        return [Finding(
            severity="info",
            title="Service-port exposure — skipped for private/RFC1918 target",
            evidence=f"host={host} resolved to {resolved_ip} (private range). "
                       f"Set WPSECSCAN_SCAN_LAN=1 to override (will probe 14 well-known service ports).",
            remediation="No action.", url=ctx["target"],
        )]

    exposed: list[tuple[int, str, str]] = []
    for port, label, advice in SERVICES:
        step(f"port probe: {host}:{port} ({label})")
        if await _try_connect(host, port):
            exposed.append((port, label, advice))

    if not exposed:
        return [Finding(severity="info", title="Service-port exposure — no high-risk ports open",
                        evidence=f"Probed {len(SERVICES)} suspect ports on {host}.",
                        remediation="No action.", url=ctx["target"])]

    for port, label, advice in exposed:
        sev = "critical" if port in (6379, 11211, 27017, 9200) else "high"
        findings.append(Finding(
            severity=sev,
            title=f"{label} reachable on {host}:{port}",
            evidence=f"TCP connect to {host}:{port} succeeded within 1s — service is publicly bound.",
            remediation=advice,
            url=f"{ctx['target']}:{port}",
        ))
    return findings
