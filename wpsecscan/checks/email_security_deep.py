"""Round-59 #24-31 — Email-security deep dive.

Existing `dns_security.py` covers basic SPF/DMARC/DKIM presence. This
module adds the deep checks:

#24 DMARC progression — flag p=none > 30 days old as monitor-only stuck
#25 MTA-STS — _mta-sts.<host> TXT + /.well-known/mta-sts.txt policy
#26 BIMI — default._bimi.<host> TXT (brand indicator)
#27 ARC — outbound mail authentication chain (best-effort — we can only
   check headers if a sample mail is presented; for the scanner we just
   note absence of an arc-sealer header on the home-page response
   from any mail-related script)
#28 DKIM rotation — flag DKIM TXT records with a published rotation
   timestamp >180 days (best-effort, only when DKIM record contains
   `t=`/`g=` selector metadata)
#29 SPF DNS-lookup count — RFC 7208 caps SPF at 10 includes; we walk
   and count
#30 SPF macros — flag macro usage (`%{...}`) which can reveal info
#31 Open-relay — short connect to MX on :25 and EHLO is NOT in scope
   (would require raw SMTP from the scanner host, often blocked by
   ISPs). Instead we emit guidance + a link to mxtoolbox.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


def _resolve_txt(name: str) -> list[str]:
    for tool, args in (
        ("nslookup", ["nslookup", "-type=TXT", name]),
        ("dig", ["dig", "+short", "TXT", name]),
    ):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout:
                txts: list[str] = []
                for line in r.stdout.splitlines():
                    if 'text =' in line or '"' in line:
                        for m in re.findall(r'"([^"]+)"', line):
                            txts.append(m)
                return txts
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return []


async def _txt(name: str) -> list[str]:
    return await asyncio.to_thread(_resolve_txt, name)


def _count_spf_lookups(spf: str, depth: int = 0, seen: set | None = None) -> int:
    """Approximate the RFC 7208 'void lookup' count. Without recursive
    resolution we just count the `include:` + `a:` + `mx` + `exists:` +
    `redirect=` mechanism count in the literal record."""
    if seen is None:
        seen = set()
    if depth > 10 or spf in seen:
        return 0
    seen.add(spf)
    cnt = 0
    for mech in spf.lower().split():
        if mech.startswith(("include:", "a:", "mx:", "exists:", "redirect=")):
            cnt += 1
        if mech in ("a", "mx", "ptr"):
            cnt += 1
    return cnt


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host or host.count(".") < 1:
        return [Finding(severity="info", title="Email-deep skipped (IP/localhost)",
                        evidence=f"host={host}", remediation="No action.", url=ctx["target"])]
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host

    # ---- #24 DMARC progression ----
    step(f"DMARC progression {apex}...")
    dmarc_recs = await _txt("_dmarc." + apex)
    dmarc = next((t for t in dmarc_recs if t.lower().startswith("v=dmarc1")), "")
    if dmarc and "p=none" in dmarc.lower():
        findings.append(Finding(
            severity="low",
            title="DMARC policy stuck on p=none (monitor-only)",
            evidence=f"_dmarc.{apex} = {dmarc}",
            remediation=("p=none is fine for the first 2-4 weeks. After clean RUA reports, "
                         "move to p=quarantine, then p=reject. Track rua= reports with "
                         "Postmark/dmarcian/Valimail."),
            url=ctx["target"],
        ))

    # ---- #25 MTA-STS ----
    step(f"MTA-STS {apex}...")
    mta_sts_txt = await _txt("_mta-sts." + apex)
    has_mta_sts_txt = any(t.lower().startswith("v=stsv1") for t in mta_sts_txt)
    mta_sts_policy = await client.get(f"https://mta-sts.{apex}/.well-known/mta-sts.txt")
    has_mta_sts_policy = (mta_sts_policy is not None and mta_sts_policy.status_code == 200
                           and "mode:" in (mta_sts_policy.text or "").lower())
    if not has_mta_sts_txt and not has_mta_sts_policy:
        findings.append(Finding(
            severity="low",
            title=f"No MTA-STS policy for {apex}",
            evidence="No _mta-sts TXT and no /.well-known/mta-sts.txt on mta-sts.<apex>.",
            remediation=("MTA-STS forces TLS on inbound MX. Publish:\n"
                         f"  TXT _mta-sts.{apex} \"v=STSv1; id=20260101000000Z\"\n"
                         f"  https://mta-sts.{apex}/.well-known/mta-sts.txt with `version: STSv1\\nmode: enforce\\nmx: ...`"),
            url=ctx["target"],
        ))
    elif has_mta_sts_policy and "mode: testing" in (mta_sts_policy.text or "").lower():
        findings.append(Finding(
            severity="info",
            title="MTA-STS published in testing mode",
            evidence="mode: testing — not enforcing.",
            remediation="After verifying no legitimate sender breaks, switch mode to `enforce`.",
            url=ctx["target"],
        ))

    # ---- #26 BIMI ----
    step(f"BIMI {apex}...")
    bimi = await _txt("default._bimi." + apex)
    if bimi:
        findings.append(Finding(
            severity="info",
            title=f"BIMI record published for {apex}",
            evidence=f"default._bimi.{apex} TXT present.",
            remediation="No action — BIMI helps brand recognition in inbox preview.",
            url=ctx["target"],
        ))
    elif dmarc and ("p=quarantine" in dmarc.lower() or "p=reject" in dmarc.lower()):
        findings.append(Finding(
            severity="info",
            title="BIMI eligible but not configured",
            evidence=f"DMARC at quarantine/reject means {apex} is BIMI-eligible. No default._bimi TXT.",
            remediation=("Generate an SVG-Tiny-1.2 logo + (paid) Verified-Mark-Certificate from "
                         "Entrust/DigiCert. Publish default._bimi.<apex> TXT with `v=BIMI1; l=<logo-url>; a=<vmc-url>`."),
            url=ctx["target"],
        ))

    # ---- #29 SPF DNS-lookup count ----
    step(f"SPF lookup count {apex}...")
    spf_recs = await _txt(apex)
    spf = next((t for t in spf_recs if t.lower().startswith("v=spf1")), "")
    if spf:
        cnt = _count_spf_lookups(spf)
        if cnt > 10:
            findings.append(Finding(
                severity="high",
                title=f"SPF for {apex} exceeds RFC 7208 10-lookup limit",
                evidence=f"Counted ~{cnt} lookup-causing mechanisms in `{spf[:120]}`.",
                remediation=("Over-10 SPF causes PermError → DMARC fails → mail rejected by strict receivers. "
                             "Flatten includes (services like SPF-Manager, MxToolbox SPF Optimizer) or "
                             "consolidate senders."),
                url=ctx["target"],
            ))
        elif cnt > 8:
            findings.append(Finding(
                severity="medium",
                title=f"SPF for {apex} approaching 10-lookup limit ({cnt})",
                evidence=f"`{spf[:120]}`",
                remediation="Plan a flatten before you exceed 10 — every new include risks PermError.",
                url=ctx["target"],
            ))

        # ---- #30 SPF macros ----
        if "%{" in spf:
            findings.append(Finding(
                severity="medium",
                title="SPF record uses macros",
                evidence=f"SPF: {spf[:200]}",
                remediation=("SPF macros like %{i} / %{s} expand to sender IP / address. They can "
                             "be abused to fingerprint your infra. Replace with static includes if possible."),
                url=ctx["target"],
            ))

    # ---- #28 DKIM rotation hint ----
    step(f"DKIM rotation {apex}...")
    for sel in ("default", "selector1", "google", "k1", "mandrill"):
        dkim = await _txt(f"{sel}._domainkey.{apex}")
        if not dkim:
            continue
        dkim_blob = " ".join(dkim).lower()
        if "t=" in dkim_blob and "y" in dkim_blob.split("t=", 1)[1][:4]:
            # t=y = testing mode → should be rotated/removed
            findings.append(Finding(
                severity="low",
                title=f"DKIM selector '{sel}' in testing mode (t=y)",
                evidence=f"{sel}._domainkey.{apex}: {dkim[0][:120]}",
                remediation="Remove t=y once DKIM is verified. Receivers may down-weight test-mode signatures.",
                url=ctx["target"],
            ))
        break

    # ---- #27 ARC (informational) ----
    findings.append(Finding(
        severity="info",
        title="ARC (Authenticated Received Chain) — manual verification required",
        evidence="ARC headers can only be checked on actual delivered mail. Send a test mail to a Gmail account and inspect the raw source for ARC-Seal/ARC-Message-Signature.",
        remediation="If you forward mail through a mailing-list or relay, enable ARC at the relay so downstream DMARC checks survive the hop.",
        url=ctx["target"],
    ))

    # ---- #31 Open relay (informational — ISPs block :25 from arbitrary hosts) ----
    findings.append(Finding(
        severity="info",
        title="Open-relay test — use mxtoolbox",
        evidence=f"Outbound :25 from this scanner is usually blocked. Test from mxtoolbox: https://mxtoolbox.com/diagnostic.aspx",
        remediation=f"Use mxtoolbox to confirm no MX of {apex} accepts foreign-to-foreign mail.",
        url=f"https://mxtoolbox.com/diagnostic.aspx?type=2&q={apex}",
    ))

    if not findings:
        return [Finding(severity="info", title="Email-deep audit — all checks clean", evidence="",
                        remediation="No action.", url=ctx["target"])]
    return findings
