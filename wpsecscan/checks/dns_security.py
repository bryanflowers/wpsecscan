"""DNS-level security audit: SPF / DMARC / DKIM presence + strictness.

Uses the stdlib `socket` resolver via `asyncio.to_thread` so we don't pull
in `dnspython`. We send no real DNS packets through our HTTP client — these
are direct system DNS queries.

Only TXT records are inspected. For DKIM we test the common 'default' selector
(only confidence indicator, not authoritative — proper DKIM verification needs
the publishing selector, which we can't enumerate from outside).
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


def _resolve_txt(name: str) -> list[str]:
    """Use socket.getaddrinfo-adjacent trick — actually we need dns. Fall back
    to nothing if no resolver is available."""
    # stdlib doesn't expose TXT lookups directly. Use shell `nslookup` /
    # `dig` if available. Otherwise return empty (graceful degrade).
    import subprocess
    for tool, args in (
        ("nslookup", ["nslookup", "-type=TXT", name]),
        ("dig", ["dig", "+short", "TXT", name]),
    ):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout:
                txts: list[str] = []
                for line in r.stdout.splitlines():
                    line = line.strip()
                    # nslookup: look for `"v=spf1 ..."` after "text =" or just quoted strings
                    if 'text =' in line or '"' in line:
                        # Pull out the quoted-string contents
                        import re as _re
                        for m in _re.findall(r'"([^"]+)"', line):
                            txts.append(m)
                return txts
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
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

    return findings
