"""Round-59 #32-39 — DNS deep-dive audit.

#32 DNSSEC — RRSIG/DNSKEY presence
#33 CAA — `CAA 0 issue "..."` records (cert-issuance control)
#34 TXT secret scan — look for accidentally-published API keys / tokens
#35 DoH — does the apex publish a SVCB/HTTPS record advertising DoH?
#36 Resolver fingerprint — what resolver answers? (Cloudflare / Google /
   on-prem)
#37 Glue records — apex NS pointing to in-bailiwick records present?
   (presence = good, absence = lame delegation risk)
#38 Wildcard — does `*-nonexistent-abcdef.apex` resolve? indicates
   wildcard A/CNAME (info-leak + brand-impersonation risk)
#39 PTR — does the apex IP reverse-resolve to the apex? mismatch is
   common but worth flagging
"""
from __future__ import annotations

import asyncio
import re
import socket
import subprocess
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


SECRET_RES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                              # AWS access key
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),                          # Google API
    re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),              # Stripe
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}"),                    # Slack
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),                            # GitHub PAT
)


def _dig(record_type: str, name: str, *, short: bool = True) -> str:
    args = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return r.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""


def _nslookup(record_type: str, name: str) -> str:
    try:
        r = subprocess.run(["nslookup", "-type=" + record_type, name],
                           capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return r.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""


def _resolve(record_type: str, name: str) -> str:
    """Try dig first; fall back to nslookup. Returns stdout or empty."""
    out = _dig(record_type, name)
    if out:
        return out
    return _nslookup(record_type, name)


async def _q(record_type: str, name: str) -> str:
    return await asyncio.to_thread(_resolve, record_type, name)


def _safe_a_lookup(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return ""


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host or host.count(".") < 1:
        return [Finding(severity="info", title="DNS-deep skipped (IP/localhost)",
                        evidence=f"host={host}", remediation="No action.", url=ctx["target"])]
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host

    # ---- #32 DNSSEC ----
    step(f"DNSSEC {apex}...")
    dnskey = await _q("DNSKEY", apex)
    if not dnskey.strip():
        findings.append(Finding(
            severity="low",
            title=f"No DNSSEC (DNSKEY) for {apex}",
            evidence="No DNSKEY records returned.",
            remediation=("Enable DNSSEC at your registrar + DNS host. Mitigates cache-poisoning + "
                         "improves MTA-STS / DANE assurance. Most providers (Cloudflare, Route 53, Bunny) "
                         "are one-click."),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"DNSSEC active on {apex}",
            evidence="DNSKEY present.", remediation="No action.", url=ctx["target"],
        ))

    # ---- #33 CAA ----
    step(f"CAA {apex}...")
    caa = await _q("CAA", apex)
    if not caa.strip():
        findings.append(Finding(
            severity="low",
            title=f"No CAA record on {apex}",
            evidence="No `CAA 0 issue ...` records.",
            remediation=("Publish CAA to restrict which CAs may issue certs for the domain. Example:\n"
                         f"  {apex}. CAA 0 issue \"letsencrypt.org\"\n"
                         f"  {apex}. CAA 0 issuewild \";\"  (disallow wildcards)"),
            url=ctx["target"],
        ))

    # ---- #34 TXT secret scan ----
    step(f"TXT secret-scan {apex}...")
    txt_blob = await _q("TXT", apex)
    leaks = []
    for r in SECRET_RES:
        for m in r.finditer(txt_blob):
            leaks.append(m.group(0))
    if leaks:
        findings.append(Finding(
            severity="critical",
            title=f"Secret pattern in TXT records on {apex}",
            evidence=", ".join(s[:8] + "..." for s in leaks[:5]),
            remediation=("ROTATE these credentials IMMEDIATELY (they're public). Replace the TXT "
                         "verification with a fresh token that you delete after the verifying party confirms."),
            url=ctx["target"],
        ))

    # ---- #35 DoH (SVCB/HTTPS) ----
    step(f"HTTPS svc record {apex}...")
    https_rr = await _q("HTTPS", apex)
    if "alpn=" in https_rr.lower() or "h3" in https_rr.lower():
        findings.append(Finding(
            severity="info",
            title=f"HTTPS SVCB record published for {apex}",
            evidence=f"{https_rr.strip()[:200]}",
            remediation="No action — clients can discover HTTP/3 + DoH endpoints via this record.",
            url=ctx["target"],
        ))

    # ---- #36 Resolver fingerprint ----
    step("resolver fingerprint...")
    out = _dig("TXT", "whoami.cloudflare", short=False) or _nslookup("TXT", "whoami.cloudflare")
    resolver = None
    if "cloudflare" in out.lower():
        resolver = "Cloudflare 1.1.1.1"
    else:
        out2 = _dig("TXT", "o-o.myaddr.l.google.com")
        if out2.strip():
            resolver = "Google 8.8.8.8"
    if resolver:
        findings.append(Finding(
            severity="info",
            title=f"Recursive resolver: {resolver}",
            evidence="Detected via well-known resolver-fingerprint queries.",
            remediation="Informational — confirms which resolver the scanner host uses.",
            url=ctx["target"],
        ))

    # ---- #37 Glue records ----
    step(f"glue records for {apex}...")
    ns = await _q("NS", apex)
    if ns.strip():
        ns_lines = [n.rstrip(".") for n in ns.split() if n.strip()]
        in_bailiwick = any(n.endswith("." + apex) or n == apex for n in ns_lines)
        if in_bailiwick:
            findings.append(Finding(
                severity="info",
                title=f"In-bailiwick NS records found for {apex}",
                evidence=", ".join(ns_lines[:5]),
                remediation="No action — glue records are correctly published.",
                url=ctx["target"],
            ))

    # ---- #38 Wildcard ----
    step("wildcard probe...")
    rand = "wpsecscan-nx-" + "abcdef9012"
    wild_ip = _safe_a_lookup(f"{rand}.{apex}")
    if wild_ip:
        findings.append(Finding(
            severity="medium",
            title=f"Wildcard DNS record active on *.{apex}",
            evidence=f"{rand}.{apex} resolves to {wild_ip}",
            remediation=("Wildcard A/CNAME records make subdomain enumeration noisy and increase "
                         "phishing risk (attackers register `paypal-update.victim.com` and it just works). "
                         "Replace with explicit records or a 404 server-block."),
            url=ctx["target"],
        ))

    # ---- #39 PTR ----
    step("PTR check...")
    apex_ip = _safe_a_lookup(apex)
    if apex_ip:
        try:
            rev = socket.gethostbyaddr(apex_ip)[0]
            if apex.lower() not in rev.lower():
                findings.append(Finding(
                    severity="info",
                    title=f"PTR for {apex} does not match",
                    evidence=f"{apex} -> {apex_ip} -> {rev}",
                    remediation=("Reverse-DNS mismatch is normal for shared hosting / CDNs. For "
                                 "dedicated mail-sending IPs, the PTR should match the HELO/EHLO hostname."),
                    url=ctx["target"],
                ))
        except (socket.herror, socket.gaierror, OSError):
            pass

    if not findings:
        return [Finding(severity="info", title="DNS-deep audit — all checks clean",
                        evidence="", remediation="No action.", url=ctx["target"])]
    return findings
