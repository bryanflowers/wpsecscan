"""#36-43 — OSINT enrichment check.

Wraps wpsecscan/integrations/osint.py — resolves target IP, looks up ASN +
geo, checks for active bug-bounty programme, lists recent cert issuances.
All best-effort, all info-level.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding
from ..integrations import osint as _osint


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        return [Finding(severity="info", title="OSINT enrich skipped (no host)",
                        evidence="Couldn't parse host.", remediation="No action.", url=ctx["target"])]

    try:
        ip = socket.gethostbyname(host)
    except OSError:
        ip = None

    if ip:
        step(f"OSINT: ASN + geo for {ip}...")
        asn = _osint.asn_for_ip(ip)
        geo = _osint.geo_for_ip(ip)
        bits = []
        if asn:
            bits.append(f"ASN: {asn.get('org', '?')}  ({asn.get('country', '?')})")
        if geo:
            bits.append(f"Geo: {geo.get('city', '?')}, {geo.get('country', '?')}  · ISP: {geo.get('isp', '?')}")
        if bits:
            findings.append(Finding(
                severity="info",
                title=f"OSINT: {ip} — {bits[0] if bits else 'no data'}",
                evidence="\n".join(bits),
                remediation="No action.",
                url=ctx["target"],
            ))

    step("OSINT: bug-bounty programme search...")
    bounty = _osint.find_bounty_program(host)
    if bounty:
        findings.append(Finding(
            severity="info",
            title=f"Bug-bounty programme found on {bounty['platform']}",
            evidence=f"Programme page: {bounty['url']}",
            remediation="If you intend to test for bounties, read the programme's scope + rules first.",
            url=bounty['url'],
        ))

    step("OSINT: recent cert issuances (last 7d)...")
    fresh = _osint.recent_cert_issuances(host, since_days=7)
    if fresh:
        sev = "medium" if len(fresh) > 3 else "info"
        findings.append(Finding(
            severity=sev,
            title=f"Cert-transparency: {len(fresh)} cert(s) issued for *.{host} in the last 7d",
            evidence="\n".join(f"  - {f['name']} issued {f['issued']} by {f['issuer'][:50]}" for f in fresh[:8]),
            remediation="If any cert name is unexpected, suspect domain hijacking / certificate-issuance fraud. Verify against your CA dashboard.",
            url=f"https://crt.sh/?q=%25.{host}",
        ))

    if not findings:
        return [Finding(severity="info", title="OSINT enrichment — no notable signals",
                        evidence="ASN/geo/bug-bounty/cert-history queries returned nothing of note.",
                        remediation="No action.", url=ctx["target"])]
    return findings
