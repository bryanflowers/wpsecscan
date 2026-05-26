"""DNS-level security audit: SPF / DMARC / DKIM + WHOIS/RDAP domain expiry.

Uses the stdlib `socket` resolver via `asyncio.to_thread` so we don't pull
in `dnspython`. We send no real DNS packets through our HTTP client — these
are direct system DNS queries.

WHOIS/expiry uses RDAP (RFC 9083) via rdap.org — no extra dependency. Some
TLDs (notably .uk, some ccTLDs) don't expose expiry over public RDAP; in
that case the check returns info and moves on.
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


# DNS labels must match RFC 1035 letters/digits/hyphen. Validated before
# passing to nslookup/dig so a hostname like `-v` can't be misinterpreted
# as a flag, and so a label containing shell metacharacters can't be
# weaponised even though we already use the list form of subprocess.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$")


def _is_safe_dns_name(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(p) for p in name.split(".") if p)


def _parse_rdap_expiry(payload: dict) -> tuple[str | None, int | None]:
    """Return (eventDate, days_until_expiry) from an RDAP domain payload."""
    for ev in payload.get("events", []) or []:
        if (ev.get("eventAction") or "").lower() == "expiration":
            raw = ev.get("eventDate") or ""
            if not raw:
                continue
            # RDAP eventDate is ISO 8601 (RFC 3339). Strip trailing Z if present.
            iso = raw.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(iso)
            except ValueError:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            days = (dt - datetime.now(timezone.utc)).days
            return raw, days
    return None, None


async def _whois_expiry_finding(apex: str) -> Finding | None:
    """RDAP lookup via rdap.org. Returns a Finding when expiry is within 60 days,
    otherwise returns None (no news is good news — keeps reports quiet)."""
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    url = f"https://rdap.org/domain/{apex}"
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0,
                                     headers={"User-Agent": "WPSecScan/dns"}) as c:
            r = await c.get(url)
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    event_date, days = _parse_rdap_expiry(data)
    if days is None:
        return None
    if days < 0:
        return Finding(
            severity="critical",
            title=f"Domain {apex} EXPIRED {abs(days)} days ago",
            evidence=f"RDAP expiration: {event_date}",
            remediation="Renew the domain immediately and verify auto-renew is enabled with the registrar.",
            url=url,
            extra={"days_until_expiry": days, "rdap_url": url},
        )
    if days < 30:
        return Finding(
            severity="high",
            title=f"Domain {apex} expires in {days} day(s)",
            evidence=f"RDAP expiration: {event_date}",
            remediation="Renew NOW. A lapsed domain takes the site offline and risks loss-to-third-party registration.",
            url=url,
            extra={"days_until_expiry": days, "rdap_url": url},
        )
    if days < 60:
        return Finding(
            severity="medium",
            title=f"Domain {apex} expires in {days} day(s)",
            evidence=f"RDAP expiration: {event_date}",
            remediation="Verify auto-renew with the registrar. Set a calendar reminder if unsure.",
            url=url,
            extra={"days_until_expiry": days, "rdap_url": url},
        )
    return None


def _resolve_txt(name: str) -> list[str]:
    """Look up TXT records via nslookup or dig (whichever is on PATH).

    Returns an empty list if no resolver is available OR if the lookup
    legitimately produced no records. Previously this exited on the first
    tool whose stdout was non-empty — but on Windows nslookup always emits
    "Server:/Address:" lines, so dig was never tried and SPF/DMARC/DKIM
    checks silently reported "missing" even when records existed.
    """
    # Defence-in-depth: never pass a hostname that doesn't pass DNS-label
    # validation to a subprocess. Already list-form, but a label like `-v`
    # would still be parsed by nslookup as a flag.
    if not _is_safe_dns_name(name):
        return []
    for tool, args in (
        ("nslookup", ["nslookup", "-type=TXT", name]),
        ("dig", ["dig", "+short", "TXT", name]),
    ):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=8)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
        if r.returncode != 0:
            continue
        txts: list[str] = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if '"' in line:
                # nslookup: quoted strings, possibly preceded by `text =`.
                for m in re.findall(r'"([^"]+)"', line):
                    txts.append(m)
            elif tool == "dig":
                # dig +short TXT emits unquoted bare strings like
                # `v=spf1 include:_spf.google.com ~all`. Accept them when
                # they look like TXT records (have at least one '=' or
                # known TXT-style prefix).
                if "=" in line or line.startswith(("v=", "google-")):
                    txts.append(line)
        if txts:
            return txts
        # Fall through to the next tool if this one produced no records
        # (Windows nslookup always prints Server:/Address: noise).
    return []


async def _txt(name: str) -> list[str]:
    return await asyncio.to_thread(_resolve_txt, name)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host or host.count(".") < 1:
        findings.append(
            Finding(
                severity="info",
                title="DNS security check skipped (target is IP / localhost)",
                evidence=f"target host: {host}",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Use apex domain for TXT lookups
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host

    # SPF
    step(f"querying SPF for {apex}...")
    spf_records = [t for t in await _txt(apex) if t.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(
            Finding(
                severity="medium",
                title=f"No SPF record on {apex}",
                evidence=(
                    "No `v=spf1 ...` TXT record at the apex. Mail purporting to come from this domain "
                    "can't be verified by recipient servers, making spoofing trivial."
                ),
                remediation=(
                    "Publish an SPF record. Minimum for a site that doesn't send mail:\n"
                    "  v=spf1 -all\n"
                    "Or, if mail comes from your hosting provider, the provider's published include + ~all:\n"
                    "  v=spf1 include:_spf.providerhost.com ~all"
                ),
                url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{apex}",
            )
        )
    else:
        spf = spf_records[0]
        weak_all = spf.lower().endswith("+all") or "?all" in spf.lower()
        findings.append(
            Finding(
                severity="medium" if weak_all else "info",
                title=f"SPF present on {apex}: {spf[:80]}",
                evidence=f"TXT record: {spf}",
                remediation=(
                    "Tighten SPF to `-all` (hard fail) instead of `+all` / `?all` (no enforcement)."
                    if weak_all else "No action needed."
                ),
                url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{apex}",
            )
        )

    # DMARC
    step(f"querying DMARC for _dmarc.{apex}...")
    dmarc_records = [t for t in await _txt("_dmarc." + apex) if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(
            Finding(
                severity="low",
                title=f"No DMARC record at _dmarc.{apex}",
                evidence="Without DMARC, SPF/DKIM failures don't actually reject spoofed mail.",
                remediation=(
                    "Publish a DMARC TXT at _dmarc.{0}. Start in monitor mode:\n"
                    "  v=DMARC1; p=none; rua=mailto:dmarc@{0};\n"
                    "After 2-4 weeks of clean reports, move to p=quarantine, then p=reject."
                ).format(apex),
                url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{apex}",
            )
        )
    else:
        dmarc = dmarc_records[0].lower()
        if "p=none" in dmarc:
            sev = "low"
            note = "Policy is p=none — monitor only, no enforcement."
        elif "p=quarantine" in dmarc:
            sev = "info"
            note = "Policy is p=quarantine — partial enforcement."
        elif "p=reject" in dmarc:
            sev = "info"
            note = "Policy is p=reject — full enforcement (best)."
        else:
            sev = "low"
            note = "Policy field not recognized — verify the record."
        findings.append(
            Finding(
                severity=sev,
                title=f"DMARC present on _dmarc.{apex}",
                evidence=f"TXT record: {dmarc_records[0]}\n{note}",
                remediation=(
                    "Move from p=none → p=quarantine → p=reject as your reports stabilize."
                    if "p=none" in dmarc else "No action needed."
                ),
                url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{apex}",
            )
        )

    # DKIM (best-effort — only checks common selectors)
    step(f"querying DKIM common selectors for {apex}...")
    dkim_found = False
    for selector in ("default", "selector1", "google", "k1"):
        records = [t for t in await _txt(f"{selector}._domainkey.{apex}") if "v=dkim" in t.lower() or "p=" in t.lower()]
        if records:
            dkim_found = True
            findings.append(
                Finding(
                    severity="info",
                    title=f"DKIM selector '{selector}' is published",
                    evidence=f"Found DKIM at {selector}._domainkey.{apex}",
                    remediation="No action needed.",
                    url=f"https://mxtoolbox.com/SuperTool.aspx?action=dkim%3a{apex}%3a{selector}",
                )
            )
            break
    if not dkim_found:
        findings.append(
            Finding(
                severity="info",
                title=f"No DKIM record found at the common selectors for {apex}",
                evidence=(
                    "Checked: default, selector1, google, k1. DKIM uses arbitrary selector names, so absence here "
                    "isn't conclusive — your provider may use a different selector."
                ),
                remediation=(
                    "Verify DKIM via your mail provider's docs and the actual selector they publish. "
                    "If the site doesn't send mail (-all SPF), DKIM isn't strictly needed."
                ),
                url=f"https://mxtoolbox.com/SuperTool.aspx?action=dkim%3a{apex}",
            )
        )

    # WHOIS/RDAP-based domain expiry. Lapsing domains take the site offline
    # and risk loss-to-third-party registration — a high-impact, easy-to-miss
    # finding most scanners ignore.
    step(f"checking RDAP domain expiry for {apex}...")
    whois_finding = await _whois_expiry_finding(apex)
    if whois_finding is not None:
        findings.append(whois_finding)

    # Item #8 — MTA-STS / TLS-RPT / BIMI
    findings.extend(await _mta_sts_findings(apex, step))
    findings.extend(await _tls_rpt_findings(apex, step))
    findings.extend(await _bimi_findings(apex, step))

    # Item #9 — DNSSEC + DS chain
    findings.extend(await _dnssec_findings(apex, step))

    return findings


# ---------------------------------------------------------------------------
# Item #8 — MTA-STS / TLS-RPT / BIMI
# ---------------------------------------------------------------------------

async def _mta_sts_findings(apex: str, step) -> list[Finding]:
    """MTA-STS publishes via a TXT record at `_mta-sts.<apex>` AND a policy
    file at https://mta-sts.<apex>/.well-known/mta-sts.txt. We check the
    TXT record only — the policy fetch is left to the user (some test
    setups have outbound HTTPS firewalled)."""
    step(f"querying MTA-STS for _mta-sts.{apex}...")
    records = [t for t in await _txt(f"_mta-sts.{apex}") if t.lower().startswith("v=stsv1")]
    if records:
        return [Finding(
            severity="info",
            title=f"MTA-STS published on _mta-sts.{apex}",
            evidence=f"TXT record: {records[0]}",
            remediation=(
                "Verify the policy file at "
                f"https://mta-sts.{apex}/.well-known/mta-sts.txt also resolves "
                "with `mode: enforce`; the TXT record alone is the version "
                "pointer — receiving servers fetch the policy file."
            ),
            url=f"https://mta-sts.{apex}/.well-known/mta-sts.txt",
        )]
    return [Finding(
        severity="low",
        title=f"No MTA-STS record on _mta-sts.{apex}",
        evidence=(
            "Without MTA-STS, inbound mail can be downgraded to plaintext SMTP "
            "by a network attacker even if both ends support STARTTLS — there "
            "is no signal to the sender that TLS was expected."
        ),
        remediation=(
            f"Publish `v=STSv1; id=<YYYYMMDDhhmm>` TXT at _mta-sts.{apex} and "
            f"host the policy file at https://mta-sts.{apex}/.well-known/"
            "mta-sts.txt with `mode: enforce`. Start in `mode: testing` "
            "while you verify rua reports arrive cleanly."
        ),
        url=f"https://mxtoolbox.com/SuperTool.aspx?action=mta-sts%3a{apex}",
    )]


async def _tls_rpt_findings(apex: str, step) -> list[Finding]:
    step(f"querying TLS-RPT for _smtp._tls.{apex}...")
    records = [t for t in await _txt(f"_smtp._tls.{apex}") if t.lower().startswith("v=tlsrptv1")]
    if records:
        return [Finding(
            severity="info",
            title=f"TLS-RPT published on _smtp._tls.{apex}",
            evidence=f"TXT record: {records[0]}",
            remediation="No action needed.",
            url=f"https://mxtoolbox.com/SuperTool.aspx?action=tls-rpt%3a{apex}",
        )]
    return [Finding(
        severity="info",
        title=f"No TLS-RPT record on _smtp._tls.{apex}",
        evidence=(
            "TLS-RPT delivers daily reports about TLS handshake failures "
            "on inbound mail. Without it you can't tell whether MTA-STS "
            "is actually being honored by senders."
        ),
        remediation=(
            f"Publish `v=TLSRPTv1; rua=mailto:tls-reports@{apex}` TXT at "
            f"_smtp._tls.{apex}."
        ),
        url=f"https://mxtoolbox.com/SuperTool.aspx?action=tls-rpt%3a{apex}",
    )]


async def _bimi_findings(apex: str, step) -> list[Finding]:
    """BIMI requires DMARC at p=quarantine or stricter. We only flag absence
    as info; presence as info (no negative business risk to missing BIMI)."""
    step(f"querying BIMI for default._bimi.{apex}...")
    records = [t for t in await _txt(f"default._bimi.{apex}") if t.lower().startswith("v=bimi1")]
    if records:
        return [Finding(
            severity="info",
            title=f"BIMI record published on default._bimi.{apex}",
            evidence=f"TXT record: {records[0]}",
            remediation="No action needed.",
            url=f"https://bimigroup.org/",
        )]
    return []  # absence is not actionable; don't add noise


# ---------------------------------------------------------------------------
# Item #9 — DNSSEC + DS chain
# ---------------------------------------------------------------------------

async def _dnssec_findings(apex: str, step) -> list[Finding]:
    """DNSSEC presence check via dnspython when available; falls back to a
    skip if it's not installed (rather than a noisy info-finding)."""
    step(f"checking DNSSEC chain for {apex}...")
    try:
        import dns.resolver  # noqa: PLC0415
        import dns.dnssec    # noqa: PLC0415 — available in dnspython 2.x
    except ImportError:
        return [Finding(
            severity="info",
            title="DNSSEC check skipped — dnspython not installed",
            evidence="The optional `dnspython` dependency is not present.",
            remediation="`pip install dnspython` to enable DNSSEC + MX checks.",
            url=f"https://dnssec-analyzer.verisignlabs.com/{apex}",
        )]

    has_ds = False
    has_dnskey = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        try:
            ds_resp = resolver.resolve(apex, "DS")
            has_ds = bool(list(ds_resp))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                 dns.resolver.NoNameservers, Exception):
            has_ds = False
        try:
            dk_resp = resolver.resolve(apex, "DNSKEY")
            has_dnskey = bool(list(dk_resp))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                 dns.resolver.NoNameservers, Exception):
            has_dnskey = False
    except Exception:  # noqa: BLE001 — DNS resolution must never break the scan
        return []

    if has_ds and has_dnskey:
        return [Finding(
            severity="info",
            title=f"DNSSEC chain present for {apex} (DS + DNSKEY)",
            evidence=(
                "Both DS (parent-side) and DNSKEY (apex-side) records resolve. "
                "Spoofing attacks against a validating resolver should fail."
            ),
            remediation="No action needed.",
            url=f"https://dnssec-analyzer.verisignlabs.com/{apex}",
        )]
    if has_dnskey and not has_ds:
        return [Finding(
            severity="medium",
            title=f"DNSSEC partially configured on {apex} — DNSKEY present but no DS at parent",
            evidence=(
                "The apex has DNSKEY records but the parent zone has no DS. "
                "Validating resolvers will treat the zone as INSECURE, defeating "
                "DNSSEC's tamper-detection."
            ),
            remediation=(
                "Submit the DS records (KSK digest) to the registrar via the "
                "domain control panel. This typically lives under 'DNSSEC' or "
                "'Security' in the registrar UI."
            ),
            url=f"https://dnssec-analyzer.verisignlabs.com/{apex}",
        )]
    return [Finding(
        severity="low",
        title=f"DNSSEC not configured on {apex}",
        evidence=(
            "No DS at the parent and no DNSKEY at the apex. The zone is not "
            "signed; recursive resolvers cannot detect cache-poisoning attacks "
            "against this domain."
        ),
        remediation=(
            "Enable DNSSEC at the registrar AND at the authoritative DNS "
            "provider. Most registrars now expose a one-click toggle that "
            "coordinates DS + DNSKEY publication."
        ),
        url=f"https://dnssec-analyzer.verisignlabs.com/{apex}",
    )]
