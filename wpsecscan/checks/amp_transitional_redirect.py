"""A19 (v2.6.0) — AMP plugin transitional-mode open-redirect probe.

The `amp` plugin (Google AMP for WP) in 'Transitional' mode serves an
AMP variant at `?amp=1` for any URL. Some theme/AMP-plugin combinations
mishandle the redirect when `?amp=1` is paired with an open URL
parameter — the user's intended URL leaks via `Location:` header.

Passive: probe `/?amp=1&redirect_to=https://evil.example/` and check
whether the response 30x to `evil.example`.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PROBES = (
    "/?amp=1&redirect_to=https://wpsecscan-probe.example/",
    "/?amp&redirect_to=//wpsecscan-probe.example/",
    "/?amp=1&url=https://wpsecscan-probe.example/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    home = await client.get("/")
    body = (home.text or "").lower() if home else ""
    has_amp = "amp" in body and ("amphtml" in body or "/amp/" in body or "amp-version" in body)
    if not has_amp:
        return findings

    for path in _PROBES:
        step(f"AMP redirect probe: {path}")
        r = await client.get(path, follow_redirects=False)
        if r is None:
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "wpsecscan-probe.example" in loc:
            findings.append(Finding(
                severity="medium",
                title=f"AMP plugin honours external redirect parameter: {path}",
                evidence=(
                    f"GET {path} → HTTP {r.status_code}\n"
                    f"Location: {loc}\n"
                    "The AMP plugin or theme forwards the user to an arbitrary "
                    "external URL specified in the query string. This is a "
                    "phishing-toolkit primitive."
                ),
                remediation=(
                    "Update the AMP plugin to the latest version. If your theme "
                    "implements a custom AMP redirect, validate redirect targets "
                    "against an allow-list of internal paths."
                ),
                url=client.url(path),
                extra={"location": loc[:200]},
            ))
            break
    return findings
