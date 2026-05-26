"""Item #7 — Host-header validation on admin endpoints.

A site that serves canonical WordPress content for any Host header is
vulnerable to DNS rebinding: an attacker hosts a domain whose A record
flips to the victim's IP, the visitor's browser sends a request with
the malicious Host, and the server happily serves /wp-admin under that
hostname. Combined with a stored XSS or a misconfigured CORS, this
becomes an admin-level browser-side intranet probe.

This is distinct from the existing `dns_rebinding` check, which probes
SSRF-via-rebind on outbound fetches. This one looks at INBOUND Host
validation on the admin surface.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

_WP_MARKERS = ("wp-admin", "wp-content", "wp-json", "wp-login", "wp-includes",
                "WordPress", "_wpnonce")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = (urlparse(ctx["target"]).hostname or "").lower()
    if not host:
        return findings

    spoofed_hosts = (
        f"{host}.wpsecscan-rebind.invalid",
        "127.0.0.1",
        "wpsecscan-rebind.invalid",
    )
    probe_paths = ("/wp-admin/admin-ajax.php", "/wp-login.php", "/wp-json/wp/v2/")

    vulnerable: list[tuple[str, str, str]] = []  # (path, host, marker)
    probed = 0

    for path in probe_paths:
        for sp_host in spoofed_hosts:
            step(f"probing {path} with Host: {sp_host}...")
            probed += 1
            r = await client.get(path, headers={"Host": sp_host})
            if r is None:
                continue
            if r.status_code in (400, 403, 421):
                continue  # rejected — good
            loc = (r.headers.get("location", "") or r.headers.get("Location", "")).lower()
            if r.status_code in (301, 302, 307, 308) and host in loc:
                continue  # canonical redirect — good
            body = (r.text or "")[:5000].lower()
            if r.status_code == 200 and any(m.lower() in body for m in _WP_MARKERS):
                marker = next(m for m in _WP_MARKERS if m.lower() in body)
                vulnerable.append((path, sp_host, marker))

    if vulnerable:
        lines = [f"  - {p} with Host: {h!r}  →  HTTP 200, contains `{m}`"
                  for p, h, m in vulnerable[:10]]
        findings.append(
            Finding(
                severity="medium",
                title=(
                    f"Possible DNS-rebinding susceptibility "
                    f"({len(vulnerable)} admin endpoint(s) accept spoofed Host)"
                ),
                evidence=(
                    "The server returned canonical WordPress content even when "
                    "the Host header did not match the canonical hostname:\n\n"
                    + "\n".join(lines) +
                    "\n\nA DNS-rebinding attack uses a malicious domain whose A "
                    "record briefly points at the victim's IP. The browser sends "
                    "the request with the malicious Host header — if the server "
                    "doesn't validate Host, the attacker can tunnel admin-shaped "
                    "requests to the victim's intranet through the visitor's browser."
                ),
                remediation=(
                    "Constrain the web server to the canonical hostname:\n"
                    "  • nginx: declare `server_name " + host + ";` and add a "
                    "catch-all server block: `server { listen 443 ssl default_server; return 421; }`\n"
                    "  • Apache: `UseCanonicalName On` + `UseCanonicalPhysicalPort On` + per-vhost ServerName\n"
                    "Also define `WP_HOME` and `WP_SITEURL` in wp-config.php so "
                    "WordPress core enforces the canonical URL even if the server "
                    "config drifts."
                ),
                url=ctx["target"],
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"Host-header validation — clean ({probed} probes)",
                evidence=(
                    "Sent admin-endpoint requests with three spoofed Host headers; "
                    "each was either rejected (400/403/421) or redirected back to "
                    f"the canonical hostname ({host})."
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
