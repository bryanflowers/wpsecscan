"""HTTP/2 fingerprint check.

Looks at httpx-reported h2 negotiation + Server header to infer the backend
HTTP/2 stack. Modern nginx (>=1.13.10), Apache (mod_http2 >=2.4.26), litespeed,
and cloudflare each have distinctive `Server:` advertisements. Flags any
backend that's known to be EOL or has unpatched H/2 CVEs.

(httpx already negotiates h2 via the `http2=True` we pass to Client.)
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (server-banner substring, EOL/CVE notes)
KNOWN_EOL_BANNERS = {
    "apache/2.2": "Apache 2.2 series is EOL since July 2017 — many HTTP/2 CVEs unpatched.",
    "apache/2.4.6": "Apache 2.4.6 (default on RHEL 7) is missing 8 years of mod_http2 fixes.",
    "nginx/1.10": "nginx 1.10/1.11 are EOL — CVE-2018-16843/16844 stream-reset DoS unpatched.",
    "nginx/1.12": "nginx 1.12 is EOL.",
    "nginx/1.14": "nginx 1.14 is EOL.",
    "nginx/1.16": "nginx 1.16 is EOL.",
    "litespeed/5": "LiteSpeed Web Server 5.x is EOL; 6.x is current.",
    "iis/7": "IIS 7/7.5 is EOL — no longer receives HTTP/2 security fixes.",
    "iis/8": "IIS 8.0 / 8.5 is end-of-extended-support.",
    "openresty/1.13": "OpenResty 1.13 is based on nginx 1.13 (EOL).",
    "openresty/1.15": "OpenResty 1.15 is EOL.",
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("inspecting / for HTTP version and Server header...")
    r = await client.get("/")
    if r is None:
        findings.append(
            Finding(
                severity="info",
                title="HTTP/2 fingerprint check — no response from /",
                evidence="Couldn't fetch / to inspect HTTP version.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    server = (r.headers.get("server", "") or r.headers.get("Server", "")).strip()
    # httpx exposes the negotiated HTTP version via .http_version (e.g. "HTTP/2", "HTTP/1.1")
    http_version = getattr(r, "http_version", "unknown")
    server_lc = server.lower()

    eol_matches = [(banner, note) for banner, note in KNOWN_EOL_BANNERS.items() if banner in server_lc]

    if not eol_matches:
        findings.append(
            Finding(
                severity="info",
                title=f"HTTP/2 fingerprint: {http_version} via {server or 'unknown server'}",
                evidence=(
                    f"Server header: {server or '(none)'}\n"
                    f"Negotiated HTTP version: {http_version}\n"
                    "No EOL backend versions matched the banner."
                ),
                remediation=(
                    "Hide the Server header in production — exact version disclosure makes CVE matching trivial. "
                    "nginx: `server_tokens off;`  Apache: `ServerTokens Prod` + `ServerSignature Off`."
                ),
                url=ctx["target"],
            )
        )
        return findings

    for banner, note in eol_matches:
        findings.append(
            Finding(
                severity="high",
                title=f"EOL HTTP backend detected: {banner}",
                evidence=f"Server header: {server}\nNegotiated: {http_version}\n\n{note}",
                remediation=(
                    "Upgrade the web-server package to a current major. EOL HTTP/2 stacks accumulate "
                    "stream-reset DoS, rapid-reset (CVE-2023-44487), HPACK-bomb, and h2c-smuggling CVEs "
                    "that vendors no longer patch."
                ),
                url=ctx["target"],
            )
        )
    return findings
