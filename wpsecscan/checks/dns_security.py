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

    return findings
