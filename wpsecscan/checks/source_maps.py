"""Source-map exposure check.

Scans response bodies for `//# sourceMappingURL=...` comments and probes the
referenced `.map` files. A served .map exposes the full pre-minified JS source
(including bundled credentials, internal API paths, debug logging).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import Client
from ..models import Finding

SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+\.js)['\"]", re.IGNORECASE)

PAGES = ("/", "/wp-login.php", "/?p=1")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    js_urls: set[str] = set()
    # 1. Inline comments in HTML
    inline_comments: list[tuple[str, str]] = []
    for path in PAGES:
        step(f"scanning {path} for sourceMappingURL...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for m in SOURCE_MAP_RE.finditer(r.text):
            inline_comments.append((path, m.group(1)))
        # Collect script srcs to probe their own .map comments
        for sm in SCRIPT_SRC_RE.finditer(r.text):
            js_urls.add(sm.group(1))

    # 2. Probe each script source for its own sourceMappingURL comment
    referenced_maps: list[tuple[str, str]] = []
    for js_url in list(js_urls)[:20]:  # cap for speed
        step(f"checking {js_url[:60]} for source-map comment...")
        # Resolve relative URL
        if js_url.startswith("//"):
            js_url_full = "https:" + js_url
        elif js_url.startswith("/"):
            js_url_full = client.url(js_url)
        elif js_url.startswith(("http://", "https://")):
            js_url_full = js_url
        else:
            js_url_full = client.url("/" + js_url)
        r = await client.get(js_url_full)
        if r is None or not r.text:
            continue
        # Source-map comments are usually at the very end of minified JS
        tail = r.text[-2000:]
        m = SOURCE_MAP_RE.search(tail)
        if m:
            map_path = m.group(1)
            if not map_path.startswith(("http://", "https://", "//")):
                map_path = urljoin(js_url_full, map_path)
            referenced_maps.append((js_url, map_path))

    # 3. Probe each referenced map to see if it's actually served
    served_maps: list[tuple[str, str, int]] = []
    for js_url, map_url in referenced_maps[:15]:
        step(f"probing {map_url[:60]}...")
        r = await client.get(map_url)
        if r is not None and r.status_code == 200 and (r.text or "").strip().startswith(("{", "{")):
            size = len(r.content or b"")
            served_maps.append((js_url, map_url, size))

    if not (inline_comments or referenced_maps or served_maps):
        findings.append(
            Finding(
                severity="info",
                title="No source-map exposure detected",
                evidence=f"Probed {len(PAGES)} HTML pages and up to 20 JS files; no `//# sourceMappingURL=` comments led to served .map files.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    if served_maps:
        lines = "\n".join(f"  - {js_u[:80]}  ->  {m_u[:80]} ({sz} bytes)" for js_u, m_u, sz in served_maps[:10])
        findings.append(
            Finding(
                severity="high",
                title=f"{len(served_maps)} source-map file(s) served — full client source exposed",
                evidence=(
                    f"JS source maps reachable:\n{lines}\n\n"
                    "A served .map file contains the full pre-bundled source code — variable names, comments, "
                    "internal API paths, and any secret accidentally bundled at build time. Attackers diff your "
                    ".map against historical builds to extract removed secrets."
                ),
                remediation=(
                    "Stop publishing source maps to production. In your build pipeline:\n"
                    "  - webpack: `devtool: false` (or `hidden-source-map` if you want maps locally)\n"
                    "  - vite: `build.sourcemap: false`\n"
                    "  - rollup: remove the sourcemap plugin from the prod config\n"
                    "If maps are required for production debugging (Sentry, Datadog), use 'hidden-source-map' so the "
                    "comment isn't published — only the sourcemap-uploader has access to it."
                ),
                url=ctx["target"],
            )
        )
    elif referenced_maps:
        lines = "\n".join(f"  - {js[:80]}  ->  {mp[:80]}" for js, mp in referenced_maps[:10])
        findings.append(
            Finding(
                severity="low",
                title=f"sourceMappingURL comments present in {len(referenced_maps)} JS file(s) — maps not currently served but comments leak the path",
                evidence=f"References found:\n{lines}",
                remediation="Strip sourceMappingURL comments in production builds. Use `hidden-source-map` devtool option.",
                url=ctx["target"],
            )
        )

    return findings
