"""Redirect-chain analysis.

Follows redirects from / and /wp-admin/ up to 8 hops, recording every Location.
Flags:
  - Chains that bounce off-domain (potential session-cookie leak / XSS via Location)
  - Chains with HTTP→HTTPS→HTTP downgrades (mixed-content / cookie leak)
  - Excessive redirect count (>5 hops on the homepage = misconfigured)
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

MAX_HOPS = 8


async def _trace(client: Client, path: str) -> list[dict]:
    """Follow redirects manually so we can record each hop. Returns list of dicts."""
    hops: list[dict] = []
    current_path = path
    for hop in range(MAX_HOPS):
        r = await client.get(current_path, follow_redirects=False)
        if r is None:
            break
        hop_info = {
            "hop": hop + 1,
            "path": current_path,
            "status": r.status_code,
            "location": r.headers.get("location", "") or r.headers.get("Location", ""),
            "scheme": "?",
        }
        # If the path is absolute, parse it
        if current_path.startswith(("http://", "https://")):
            hop_info["scheme"] = urlparse(current_path).scheme
        hops.append(hop_info)
        if r.status_code not in (301, 302, 303, 307, 308):
            break
        loc = hop_info["location"]
        if not loc:
            break
        # Absolute next path
        if loc.startswith(("http://", "https://")):
            current_path = loc
        else:
            current_path = loc  # relative — Client.url will resolve
    return hops


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    scan_host = urlparse(ctx["target"]).hostname or ""

    for start in ("/", "/wp-admin/"):
        step(f"tracing redirect chain from {start}...")
        hops = await _trace(client, start)
        if len(hops) <= 1:
            continue

        # Build a human-readable trace
        lines = []
        offsite_jump = False
        downgrade_to_http = False
        for h in hops:
            line = f"  #{h['hop']}  HTTP {h['status']}  ({h['scheme']}) {h['path']}"
            if h["location"]:
                line += f"  ->  {h['location']}"
            lines.append(line)
            # Off-domain detection
            loc_host = urlparse(h["location"]).hostname or ""
            if loc_host and loc_host != scan_host and not loc_host.endswith("." + scan_host):
                offsite_jump = True
            # Downgrade detection — if any hop is https→http
            cur_scheme = urlparse(h["path"]).scheme or h["scheme"]
            loc_scheme = urlparse(h["location"]).scheme
            if cur_scheme == "https" and loc_scheme == "http":
                downgrade_to_http = True

        if offsite_jump:
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Redirect chain from {start} jumps off-domain",
                    evidence="Trace:\n" + "\n".join(lines) + "\n\n"
                            "An attacker controlling the off-domain step can read referrer + Set-Cookie if "
                            "the original cookies lacked SameSite.",
                    remediation=(
                        "Audit your redirect pipeline. WP shouldn't ever Location: an external host on /wp-admin/. "
                        "If this is a custom plugin doing it, use wp_safe_redirect() instead."
                    ),
                    url=client.url(start),
                )
            )
        if downgrade_to_http:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Redirect chain from {start} downgrades HTTPS → HTTP",
                    evidence="Trace:\n" + "\n".join(lines) + "\n\n"
                            "Any cookie or auth token gets sent over plaintext after the downgrade.",
                    remediation=(
                        "Force HTTPS everywhere. In wp-config: `define('FORCE_SSL_ADMIN', true);`\n"
                        "At the server: a permanent 301 from http://* to https://* on all paths."
                    ),
                    url=client.url(start),
                )
            )
        if len(hops) >= 5:
            findings.append(
                Finding(
                    severity="low",
                    title=f"Redirect chain from {start} is {len(hops)} hops long",
                    evidence="Trace:\n" + "\n".join(lines) + "\n\n"
                            "Long chains slow page loads and can mask misconfigs.",
                    remediation="Consolidate redirects. Check WP Settings → General for siteurl/home matching.",
                    url=client.url(start),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Redirect chains look clean",
                evidence="No off-domain hops, no HTTPS→HTTP downgrades, no excessive chain length from /, /wp-admin/.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
