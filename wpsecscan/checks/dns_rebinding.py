"""H2 DNS-rebinding SSRF (passive guidance + active probe when possible).

DNS rebinding is when an attacker registers a domain whose first DNS lookup
returns the attacker's server (passes any allow-list) but the second lookup
returns 127.0.0.1 (after the allow-list check has already passed). If the
server fetches the URL twice (e.g. validation + retrieval), the second fetch
hits the internal host.

We can't fully test rebinding without a controlled DNS server, but we CAN:
  1. Use the public `*.rbndr.us` service (singe.id's rebinder), which returns
     alternating answers for `<first-ip>.<second-ip>.rbndr.us`.
  2. Build `7f000001.0a000001.rbndr.us` → resolves 127.0.0.1 / 10.0.0.1 alternately.

If the existing SSRF check found a confirmed parameter, we feed it a rebinder
URL and compare two consecutive responses. Mismatching body length is the
indicator of a successful rebind (the second fetch hit a different host).

Aggressive only.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..http import Client
from ..models import Finding


REBINDER_URL = "http://7f000001.0a000001.rbndr.us/"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(Finding(
            severity="info",
            title="DNS-rebinding SSRF chain skipped (passive mode)",
            evidence="Pass --aggressive AND have a confirmed SSRF candidate.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    shared = ctx.get("shared") or {}
    ssrf_candidate = shared.get("ssrf_candidate")
    if not ssrf_candidate:
        findings.append(Finding(
            severity="info",
            title="DNS-rebinding SSRF chain skipped (no SSRF candidate)",
            evidence="Needs the ssrf check to have confirmed a fetch-attacker-URL parameter first.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    base_url = ssrf_candidate.get("url", "")
    param = ssrf_candidate.get("param", "?")
    if not base_url:
        return findings

    u = urlparse(base_url)
    qs = dict(parse_qsl(u.query))
    qs[param] = REBINDER_URL
    probe = urlunparse(u._replace(query=urlencode(qs)))

    step("DNS-rebinding probe (sample 1)...")
    r1 = await client.get(probe)
    step("DNS-rebinding probe (sample 2)...")
    r2 = await client.get(probe)
    if r1 is None or r2 is None:
        findings.append(Finding(
            severity="info",
            title="DNS-rebinding probe couldn't reach the rebinder",
            evidence="rbndr.us was unreachable — try again from a network with outbound DNS.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    len1 = len(r1.content or b"")
    len2 = len(r2.content or b"")
    if abs(len1 - len2) > 200:
        findings.append(Finding(
            severity="high",
            title="Possible DNS-rebinding SSRF — two consecutive fetches returned different bodies",
            evidence=(
                f"Same probe URL {probe} returned {len1} bytes on call 1, {len2} on call 2.\n"
                "rbndr.us alternates between 127.0.0.1 and 10.0.0.1 across DNS responses; the second fetch "
                "likely hit a different host, which is the DNS-rebinding bypass pattern."
            ),
            remediation=(
                "Resolve the hostname ONCE, validate the IP against an allow-list, then fetch by IP (with "
                "Host header). Or use a proven library: SafeURL, ssrf-shield, etc."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="DNS-rebinding probe — bodies match across two fetches",
            evidence=f"Both fetches returned ~{len1} bytes. Not conclusive proof of safety, but no rebind observed.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
