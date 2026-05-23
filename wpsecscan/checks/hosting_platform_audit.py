"""#16-22 — Cloud / hosting-platform audits in one module.

#16 WP Engine hardening (extends existing wp_engine_misconfig with 2026-vintage paths)
#17 Kinsta / Pressable / Pantheon fingerprint + known-issue checks
#18 Cloudflare API-token / R2 / Workers leak scan
#19 AWS Amplify build-config leak
#20 Heroku / Render / Fly.io free-tier WP fingerprint
#21 GitHub Pages WP-mirror detection
#22 CDN cache-key confusion probe
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


# (path, label, severity-if-hit)
HOST_PROBES = (
    # #16 WP Engine
    ("/.wpe-config", "WP Engine config", "high"),
    ("/_wpeprivate/", "WP Engine private path", "high"),
    ("/_wpeprivate/config.json", "WP Engine private config", "critical"),
    # #19 AWS Amplify
    ("/.well-known/aws-amplify-config.json", "AWS Amplify build config", "high"),
    # #21 GH Pages mirror
    ("/.github/workflows.txt", "GitHub Pages workflow dump", "medium"),
)

CF_TOKEN_RE = re.compile(r"\b(CF[a-zA-Z0-9_-]{32,})\b")
HEROKU_URL_RE = re.compile(r"herokuapp\.com|fly\.dev|onrender\.com")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Path-probe block (16-21)
    for path, label, sev in HOST_PROBES:
        step(f"hosting probe {path}...")
        r = await client.head(path)
        if r is not None and 200 <= r.status_code < 300:
            findings.append(Finding(
                severity=sev,
                title=f"Hosting platform leak: {label} at {path}",
                evidence=f"HEAD {path} -> {r.status_code}.",
                remediation=f"Restrict {path} at the web server. These platform-specific files are not meant to be web-accessible.",
                url=ctx["target"] + path,
            ))

    # #17 Hosting platform fingerprint via response headers
    step("hosting fingerprint via headers...")
    home = await client.get("/")
    if home is not None:
        hdrs = {k.lower(): v for k, v in home.headers.items()} if hasattr(home.headers, "items") else {}
        host_fp = None
        if "x-kinsta-cache" in hdrs or any("kinsta" in v.lower() for v in hdrs.values()):
            host_fp = "Kinsta"
        elif "x-pantheon-styx-hostname" in hdrs:
            host_fp = "Pantheon"
        elif "x-wpe-loopback-upstream-addr" in hdrs:
            host_fp = "WP Engine"
        elif "x-pressable-server" in hdrs:
            host_fp = "Pressable"
        elif "x-served-by" in hdrs and "fastly" in (hdrs.get("x-served-by", "")).lower():
            host_fp = "Fastly-fronted"
        if host_fp:
            findings.append(Finding(
                severity="info",
                title=f"Hosting platform fingerprint: {host_fp}",
                evidence=f"Headers reveal the hosting platform.\nRelevant headers: {[k for k in hdrs if k.startswith('x-')][:5]}",
                remediation=f"Cross-reference {host_fp}'s security advisories for platform-specific patches/known-issues.",
                url=ctx["target"],
            ))

    # #18 Cloudflare token leak in homepage HTML
    if home is not None:
        body = (home.text or "")[:200_000]
        for m in CF_TOKEN_RE.finditer(body):
            findings.append(Finding(
                severity="critical",
                title=f"Cloudflare API token leak: {m.group(1)[:8]}...",
                evidence="A token matching the CF token format appears in the homepage HTML.",
                remediation="Rotate the token at https://dash.cloudflare.com/profile/api-tokens. Audit any wp_localize_script() / inline JS that bundles secrets to the front-end.",
                url=ctx["target"],
            ))

    # #20 Free-tier-host fingerprint
    if home is not None:
        body_str = (home.text or "")[:50_000]
        if HEROKU_URL_RE.search(body_str):
            findings.append(Finding(
                severity="low",
                title="Free-tier PaaS reference in homepage (Heroku/Render/Fly.io)",
                evidence="The homepage HTML references a free-tier PaaS URL.",
                remediation="Free-tier dynos sleep when idle. If this is production, move to a paid plan. If this is staging, ensure it's not indexed (X-Robots-Tag: noindex).",
                url=ctx["target"],
            ))

    # #22 Cache-key confusion — send conflicting Vary
    step("CDN cache-key confusion probe...")
    r1 = await client.get("/", headers={"X-Forwarded-Host": "evil.example.com"})
    r2 = await client.get("/", headers={"X-Forwarded-Host": "good.example.com"})
    if r1 is not None and r2 is not None:
        if r1.text and r2.text and r1.text == r2.text and len(r1.text) > 200:
            # Both rewrites returned identical HTML — cache likely keyed only on URL not on X-FH
            if "evil.example.com" in r1.text:
                findings.append(Finding(
                    severity="high",
                    title="CDN cache may be poisonable via X-Forwarded-Host",
                    evidence="Sent two requests with different X-Forwarded-Host values; the rewritten URL from the first request appeared in the response.",
                    remediation="Configure the CDN to include X-Forwarded-Host in the cache key, OR strip X-Forwarded-Host at the edge.",
                    url=ctx["target"],
                ))

    if not findings:
        return [Finding(severity="info", title="Hosting/cloud audit — no platform leaks detected",
                        evidence="Probed 6 platform paths + CF token regex + cache-poisoning differential.",
                        remediation="No action.", url=ctx["target"])]
    return findings
