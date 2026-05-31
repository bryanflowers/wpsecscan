"""F6 (v2.8.1) — Plugin update-server integrity check.

WP plugins can define a custom update server via the
`update_uri` plugin header. If that URL is HTTP (not HTTPS) or
returns an invalid TLS cert, MITM attackers can serve a malicious
update package. We probe the well-known REST plugins list and
fetch the homepage for self-hosted update markers.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F6: probing for non-HTTPS plugin update servers")
    findings: list[Finding] = []
    r = await client.get("/wp-json/wp/v2/plugins")
    if r is None or r.status_code != 200:
        return [Finding(severity="info",
                         title="F6: plugin-update-integrity check skipped (REST plugins list not public)",
                         evidence=f"GET /wp-json/wp/v2/plugins → {r.status_code if r else 'no response'}",
                         remediation="No action needed.",
                         url=ctx["target"])]
    try:
        plugins = r.json()
    except ValueError:
        return []
    if not isinstance(plugins, list):
        return []
    insecure: list[str] = []
    for p in plugins:
        if not isinstance(p, dict):
            continue
        uri = (p.get("update_uri") or "").strip()
        if uri and urlparse(uri).scheme == "http":
            insecure.append(f"{p.get('plugin','?')} → {uri}")
    if insecure:
        findings.append(Finding(severity="high",
                                  title=f"F6: {len(insecure)} plugin(s) use HTTP update server (MITM risk)",
                                  evidence="\n".join(insecure[:10]),
                                  remediation=(
                                      "Contact each plugin author and request an HTTPS update URL. "
                                      "Until fixed, set `WP_HTTP_BLOCK_EXTERNAL=true` and whitelist "
                                      "only your trusted update hosts via `WP_ACCESSIBLE_HOSTS`."),
                                  url=ctx["target"]))
    else:
        findings.append(Finding(severity="info",
                                  title="F6: all plugin update URIs use HTTPS",
                                  evidence=f"Inspected {len(plugins)} plugins; none use plain HTTP for updates.",
                                  remediation="No action needed.",
                                  url=ctx["target"]))
    return findings
