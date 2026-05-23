"""SSRF probes via WP/plugin endpoints that fetch URLs.

Common SSRF vectors:
  - oEmbed proxy `/wp-json/oembed/1.0/proxy?url=...`
  - WP image proxy or plugin endpoints (`/wp-json/<plugin>/v1/fetch?url=...`)
  - REST API edge cases
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding
from ..prove import build_replay_curl

# Use a deliberately impossible host that won't resolve. If the server tries to
# fetch it, the response time/error tells us SSRF is at play. We do NOT use
# 169.254.169.254 (cloud metadata) or rfc1918 ranges — too aggressive.
SSRF_TARGET = "https://wpsecscan-ssrf-canary.invalid/probe"

# (path, query-param name, description, severity if SSRF confirmed)
TARGETS = (
    ("/wp-json/oembed/1.0/proxy",       "url",  "WP REST oEmbed proxy",   "high"),
    ("/?rest_route=/oembed/1.0/proxy",  "url",  "WP REST oEmbed (route)", "high"),
    ("/wp-admin/admin-ajax.php",        "url",  "admin-ajax url=",        "medium"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path, param, desc, sev in TARGETS:
        step(f"probing {desc} for SSRF via ?{param}=...")
        r = await client.get(path, params={param: SSRF_TARGET})
        if r is None:
            continue
        body = (r.text or "")[:2000].lower()
        # Indicators that the server actually tried to fetch:
        # - Error mentions "could not resolve", "name or service", "getaddrinfo", "dns"
        # - 502/504 from an upstream fetch failure
        triggered = False
        why = ""
        if r.status_code in (502, 504):
            triggered = True
            why = f"HTTP {r.status_code} (gateway-like; server likely attempted upstream fetch)"
        for marker in ("could not resolve", "name or service", "getaddrinfo", "no address associated", "name resolution"):
            if marker in body:
                triggered = True
                why = f"response body contains '{marker}' — server tried to resolve attacker-controlled hostname"
                break
        if triggered:
            url = client.url(path)
            replay = build_replay_curl("GET", url, params={param: SSRF_TARGET})
            findings.append(
                Finding(
                    severity=sev,
                    title=f"SSRF indicator at {desc}",
                    evidence=(
                        f"GET {path} with {param}={SSRF_TARGET}\n  -> HTTP {r.status_code}\n  -> {why}"
                    ),
                    remediation=(
                        "Plugins that fetch URLs must validate them against an allow-list and reject "
                        "RFC1918/loopback/link-local addresses. For oEmbed specifically, recent WP versions "
                        "have hardened the proxy — make sure core and any oEmbed-handling plugin are current."
                    ),
                    url=url,
                    extra={
                        "provable": True,
                        "prover": "ssrf",
                        "endpoint": path,
                        "param": param,
                        "replay": replay,
                        "next_steps": [
                            f'curl -i "{url}?{param}=http://127.0.0.1:80/"',
                            "# Manually verify what internal services are reachable",
                        ],
                    },
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No SSRF indicators on tested endpoints",
                evidence=f"Probed {len(TARGETS)} known URL-fetching endpoints with an unresolvable canary host.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
