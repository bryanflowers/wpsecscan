"""AbuseIPDB reputation lookup.

Opt-in via --abuseipdb-token (free tier: 1000 queries/day). Resolves the target
host's IP and queries https://api.abuseipdb.com/api/v2/check for reputation
score + recent abuse reports. Flags scores >= 25 as low/medium (depending),
>= 75 as high — these often indicate compromised shared hosting.
"""
from __future__ import annotations

import asyncio
import json as _json
import socket
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _query_abuseipdb(ip: str, token: str, timeout: float = 8.0) -> dict | None:
    """Synchronous query to AbuseIPDB. Returns None on any error."""
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({
        "ipAddress": ip, "maxAgeInDays": "90", "verbose": "true",
    })
    req = urllib.request.Request(url, headers={
        "Key": token, "Accept": "application/json", "User-Agent": "WPSecScan/abuseipdb",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return _json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    token = (ctx.get("abuseipdb_token") or "").strip()
    if not token:
        findings.append(
            Finding(
                severity="info",
                title="AbuseIPDB lookup skipped (no token)",
                evidence="Pass --abuseipdb-token TOKEN to enable IP-reputation checks. "
                         "Free tier: 1000 queries/day at https://www.abuseipdb.com/account/api.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        findings.append(
            Finding(
                severity="info",
                title="AbuseIPDB lookup skipped — couldn't extract host",
                evidence=f"target: {ctx['target']}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"resolving {host}...")
    ip = await asyncio.to_thread(_resolve, host)
    if not ip:
        findings.append(
            Finding(
                severity="info",
                title=f"AbuseIPDB lookup skipped — DNS resolution failed for {host}",
                evidence="No A record returned.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"querying AbuseIPDB for {ip}...")
    data = await asyncio.to_thread(_query_abuseipdb, ip, token)
    if not data or "data" not in data:
        findings.append(
            Finding(
                severity="info",
                title=f"AbuseIPDB query failed for {ip}",
                evidence="Empty / non-200 response. Check token validity + daily quota.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    d = data["data"]
    score = d.get("abuseConfidenceScore", 0)
    reports = d.get("totalReports", 0)
    last_reported = d.get("lastReportedAt", "(never)")
    isp = d.get("isp", "(unknown)")
    country = d.get("countryCode", "??")

    if score >= 75:
        sev = "high"
        title = f"AbuseIPDB: high-confidence abuse score {score}/100 for {ip}"
    elif score >= 25:
        sev = "medium"
        title = f"AbuseIPDB: moderate abuse score {score}/100 for {ip}"
    elif score > 0:
        sev = "low"
        title = f"AbuseIPDB: low abuse score {score}/100 for {ip}"
    else:
        sev = "info"
        title = f"AbuseIPDB: clean reputation for {ip}"

    evidence = (
        f"IP: {ip}  ({host})\n"
        f"ISP: {isp}, country: {country}\n"
        f"Abuse confidence: {score}/100\n"
        f"Total reports (90d): {reports}\n"
        f"Last reported: {last_reported}\n"
        f"Detail: https://www.abuseipdb.com/check/{ip}"
    )
    remediation = (
        "No action needed if score is low. If high, your site shares an IP with a known-bad source — "
        "consider moving to a different host/IP. Shared-hosting customers often inherit a bad neighbour's "
        "reputation in spam blocklists."
    ) if sev == "info" else (
        "Investigate why this IP has been reported. If it's shared hosting, neighbour-traffic may be the "
        "cause — request an IP migration from your host. If it's dedicated, audit local processes."
    )
    findings.append(Finding(
        severity=sev,
        title=title,
        evidence=evidence,
        remediation=remediation,
        url=f"https://www.abuseipdb.com/check/{ip}",
        extra={"ip": ip, "abuse_score": score, "reports": reports},
    ))
    return findings
