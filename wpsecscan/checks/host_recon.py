"""#40 — container / cloud-native host recon.

When the WP site is hosted in a container or on a cloud VM, the underlying
host has its own attack surface (open Redis, exposed Docker socket, naked
Kubernetes API). This check probes a small set of cloud-host common ports
+ known-bad service-discovery endpoints AGAINST THE TARGET'S IP — not
side-channel scanning, just confirming what the WP-host port surface
looks like from the public internet.

Passive — TCP-only connect probes, no payload-sending. Aggressive mode
extends to send a couple of read-only fingerprint queries.

Out of scope: actual CVE matching against the discovered service banners
— that's a job for Trivy / nmap. We emit info-level findings telling the
user "consider running a host scanner against $IP".
"""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


# (port, label, severity-if-open)
HOST_PORTS = (
    (22,    "SSH",                 "info"),
    (23,    "Telnet (deprecated)", "high"),
    (2375,  "Docker daemon HTTP (no TLS)",  "critical"),
    (2376,  "Docker daemon HTTPS", "high"),
    (6379,  "Redis (typically auth-less)", "high"),
    (9200,  "Elasticsearch",       "high"),
    (27017, "MongoDB",             "high"),
    (5432,  "PostgreSQL",          "medium"),
    (3306,  "MySQL",               "medium"),
    (6443,  "Kubernetes API",      "critical"),
    (10250, "Kubelet",             "critical"),
    (11211, "memcached (data leak)", "medium"),
    (61613, "ActiveMQ STOMP",      "medium"),
    (8500,  "Consul HTTP API",     "high"),
    (8200,  "HashiCorp Vault",     "info"),
    (9092,  "Kafka",               "info"),
)


def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        return [Finding(severity="info", title="Host recon skipped (no hostname)",
                        evidence="Couldn't parse hostname from target.",
                        remediation="No action.", url=ctx["target"])]

    step(f"host port probe against {host}...")
    # Run all TCP probes in parallel via to_thread
    sem = asyncio.Semaphore(8)
    async def _check(port: int):
        async with sem:
            return await asyncio.to_thread(_tcp_connect, host, port)

    statuses = await asyncio.gather(*( _check(p) for p, _l, _s in HOST_PORTS ))
    open_ports = [(p, label, sev) for (p, label, sev), is_open in zip(HOST_PORTS, statuses) if is_open]

    if not open_ports:
        findings.append(Finding(
            severity="info",
            title=f"Host recon — no non-HTTP ports open on {host}",
            evidence=f"Probed {len(HOST_PORTS)} common service ports; none accepted a TCP connection.",
            remediation=("Consider running a deeper port scan (`nmap -p- {host}`) for full "
                          "coverage — we only probe the highest-impact ports.").format(host=host),
            url=ctx["target"],
        ))
        return findings

    # Bucket by severity
    for sev_level in ("critical", "high", "medium", "info"):
        in_level = [(p, l) for p, l, s in open_ports if s == sev_level]
        if not in_level:
            continue
        findings.append(Finding(
            severity=sev_level,
            title=f"Host recon — {len(in_level)} {sev_level}-risk service(s) reachable on {host}",
            evidence="\n".join(f"  - tcp/{p}  {label}" for p, l in in_level) + (
                "\n\nThese services live on the same IP as the WP site. Exposing them publicly "
                "is rarely intentional; in cloud setups they're meant to be locked behind a VPN "
                "or security group."),
            remediation=(
                "Restrict the listed ports to a private network / VPN. If they MUST be reachable, "
                "ensure authentication is enabled (Redis requirepass, MongoDB --auth, Docker TLS "
                "client certs, Kubernetes RBAC). Run a full Trivy / nmap scan to audit further."
            ),
            url=ctx["target"],
        ))
    return findings
