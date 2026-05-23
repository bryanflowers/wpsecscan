"""Mixed-content audit.

HTTPS pages that load HTTP resources (scripts, images, fonts) leak the page
contents to network attackers and break the integrity guarantee. Modern
browsers block most of these but legacy plugins/themes still emit them.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

# Catch http:// in attributes that load resources
HTTP_RESOURCE_RE = re.compile(
    r'(?:src|href|action|data-src|srcset|poster)=["\']http://([^"\'\s>]+)',
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    is_https = urlparse(ctx["target"]).scheme == "https"
    if not is_https:
        findings.append(
            Finding(
                severity="info",
                title="Mixed-content check skipped — site is HTTP, not HTTPS",
                evidence="The whole site is unencrypted; mixed-content is moot.",
                remediation="Serve the site over HTTPS first; then this check becomes meaningful.",
                url=ctx["target"],
            )
        )
        return findings

    PAGES = ("/", "/wp-login.php", "/?p=1", "/sample-page/")
    hosts_seen: dict[str, list[tuple[str, str]]] = {}  # host -> [(page, sample-url), ...]

    for path in PAGES:
        step(f"scanning {path} for HTTP (non-HTTPS) resources...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for m in HTTP_RESOURCE_RE.finditer(r.text):
            url_part = m.group(1)
            # Skip localhost / 127.0.0.1 / domain-relative-without-scheme
            host = url_part.split("/", 1)[0].split(":")[0]
            if host in ("localhost", "127.0.0.1") or host.endswith(".local"):
                continue
            hosts_seen.setdefault(host, []).append((path, "http://" + url_part[:120]))

    if not hosts_seen:
        findings.append(
            Finding(
                severity="info",
                title="No mixed-content (HTTP) resources detected",
                evidence=f"Scanned {len(PAGES)} pages for HTTP src=/href=/action= attributes; none found.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    total_resources = sum(len(v) for v in hosts_seen.values())
    lines = []
    for host, refs in sorted(hosts_seen.items())[:15]:
        lines.append(f"  - {host} ({len(refs)} reference(s)):")
        for page, sample in refs[:2]:
            lines.append(f"      from {page}: {sample}")

    findings.append(
        Finding(
            severity="medium",
            title=f"Mixed content: {total_resources} HTTP resource(s) loaded from {len(hosts_seen)} host(s)",
            evidence="\n".join(lines),
            remediation=(
                "Replace every http:// with https:// (or //) in your theme + plugins. Common sources:\n"
                "  - Hardcoded image URLs in posts: search-and-replace via WP-CLI: `wp search-replace 'http://yourdomain' 'https://yourdomain'`\n"
                "  - Plugin assets pinned to http:// — update the plugin or override its enqueue\n"
                "  - 3rd-party widgets (analytics, fonts) — switch to their HTTPS endpoints\n"
                "  - Browser tip: open DevTools → Console → look for 'Mixed Content' warnings"
            ),
            url=ctx["target"],
            extra={"hosts": list(hosts_seen.keys())},
        )
    )
    return findings
