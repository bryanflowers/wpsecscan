"""H3 HTTP/3 + QUIC fingerprint.

Detects whether the target advertises HTTP/3 via `Alt-Svc: h3="..."` and
identifies the QUIC implementation by reading the server header alongside.
HTTP/3-capable proxies (Cloudflare, Fastly, Caddy, LiteSpeed) advertise
themselves consistently — knowing which one matters for picking the right
WAF-bypass payloads.

This is a passive header sniff; no QUIC handshake is performed (would need
aioquic, an optional dep we don't want to require).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Common Alt-Svc h3 variants and what server they typically belong to.
SERVER_HINTS = {
    "cloudflare":   "Cloudflare",
    "envoy":        "Envoy proxy (often Istio / Lyft)",
    "litespeed":    "LiteSpeed",
    "ats":          "Apache Traffic Server",
    "caddy":        "Caddy",
    "nginx-quic":   "nginx HTTP/3 (1.25+ official)",
    "fastly":       "Fastly",
    "lite-speed":   "LiteSpeed",
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("checking Alt-Svc for HTTP/3...")
    r = await client.get("/")
    if r is None:
        findings.append(Finding(
            severity="info",
            title="HTTP/3 fingerprint — no response on /",
            evidence="Couldn't reach / to read Alt-Svc.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    alt_svc = (r.headers.get("alt-svc") or r.headers.get("Alt-Svc") or "")
    server  = (r.headers.get("server") or r.headers.get("Server") or "").lower()

    h3_advertised = "h3" in alt_svc.lower() or "h3-29" in alt_svc.lower() or "h3-32" in alt_svc.lower()
    hint = next((label for k, label in SERVER_HINTS.items() if k in server), None)

    if h3_advertised:
        findings.append(Finding(
            severity="info",
            title=f"HTTP/3 advertised via Alt-Svc{f' ({hint})' if hint else ''}",
            evidence=(
                f"Alt-Svc header: {alt_svc[:200]}\n"
                f"Server header: {server or '(absent)'}\n\n"
                "Many WAFs and CDNs apply different rules to h3 traffic — bypass attempts often hit fewer "
                "filters over QUIC than over h2. Worth re-running aggressive probes with an h3-capable client."
            ),
            remediation=(
                "Confirm your WAF inspects HTTP/3 traffic (Cloudflare/Fastly do by default; on-prem h3 "
                "behind an external WAF may not). Use h2load or curl --http3 to verify the h3 endpoint "
                "behaves identically to h2."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="HTTP/3 not advertised on /",
            evidence=f"Alt-Svc header absent or doesn't list h3. Server: {server or '(absent)'}",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
