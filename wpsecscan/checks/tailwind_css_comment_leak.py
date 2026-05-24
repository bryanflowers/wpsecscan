"""Tailwind/built-CSS comment leak audit.

Round-64 #69 — built CSS files (Tailwind, Sass output, esbuild bundles)
often leak filesystem paths from sourcemap comments or PostCSS plugins.
A typical signal is `/* C:\\Users\\... */` or `/home/<dev>/...` baked
into production CSS. Useful for an attacker doing username enumeration
or finding where to look for misconfigured staging hosts.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Patterns we want to find INSIDE CSS comments
_LEAK_PATTERNS = (
    (re.compile(r"[A-Z]:\\\\[Uu]sers\\\\[A-Za-z0-9._\\\\-]+"), "Windows user-path"),
    (re.compile(r"/home/[a-z][a-z0-9_-]+/[^\s\"]*"), "Linux home-path"),
    (re.compile(r"/Users/[A-Za-z][A-Za-z0-9._-]+/[^\s\"]*"), "macOS home-path"),
    (re.compile(r"localhost:\d{4,5}"), "localhost dev port"),
    (re.compile(r"sourceMappingURL=[^*\s]+"), "sourceMappingURL"),
    (re.compile(r"//#\s+sourceURL=[^\s]+"), "sourceURL marker"),
)

_CSS_PROBE_PATHS = (
    "/wp-content/themes/twentytwentyfour/assets/css/style.css",
    "/wp-content/themes/twentytwentythree/assets/css/style.css",
    "/wp-content/themes/twentytwentytwo/assets/css/style.css",
    "/wp-includes/css/dist/block-library/style.css",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Pull homepage to discover the actually-loaded CSS files
    step("scanning homepage for CSS hrefs...")
    home = await client.get("/")
    css_urls: list[str] = []
    if home is not None and home.status_code == 200:
        body = home.text or ""
        css_urls = re.findall(r'<link[^>]+href="([^"]+\.css(?:\?[^"]*)?)"', body, re.IGNORECASE)
    # de-dupe + cap at 12 to avoid hammering
    seen: set[str] = set()
    targets: list[str] = []
    for u in css_urls + list(_CSS_PROBE_PATHS):
        if u in seen:
            continue
        seen.add(u)
        targets.append(u)
        if len(targets) >= 12:
            break

    for url in targets:
        # If url is absolute, pull as-is via client.get with full path; else relative
        path = url if url.startswith("/") else "/" + url.lstrip("/")
        if url.startswith("http"):
            # External CDN — skip; we only audit on-site CSS
            continue
        step(f"scanning {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if "</html" in body.lower()[:1000]:
            continue  # Not actually CSS — 404 page returned 200
        # Walk CSS /* */ comments + // line comments
        comments = re.findall(r"/\*[\s\S]*?\*/", body)
        if not comments:
            continue
        comment_blob = "\n".join(comments)
        hits: list[str] = []
        for pat, name in _LEAK_PATTERNS:
            m = pat.search(comment_blob)
            if m:
                hits.append(f"{name}: {m.group(0)[:80]!r}")
        if hits:
            findings.append(
                Finding(
                    severity="low",
                    title=f"Filesystem-path leak in CSS comments: {path}",
                    evidence="\n".join(f"  {h}" for h in hits[:5]),
                    remediation=(
                        "Strip comments + sourcemaps from production CSS.\n"
                        "  Tailwind: `npx tailwindcss --minify`\n"
                        "  PostCSS: enable `cssnano` with `discardComments: { removeAll: true }`\n"
                        "  esbuild: `--legal-comments=none`\n"
                        "Reveals dev usernames + local dev-server ports."
                    ),
                    url=client.url(path),
                )
            )

    return findings
