"""WordPress core version detection.

Looks for the core version in the <meta name="generator"> tag on /, then in
the /feed/ <generator> element, and always requests /readme.html, which is
reported (medium) when it is public and shows a version. The result is stored
in ctx['shared']['wp_version'] for other checks. It then asks
api.wordpress.org for the latest release, a request that leaves the target:
older than latest is high, current is info, and an unreachable API leaves a
medium disclosure finding. No version found yields one info finding. Fix:
update core, delete readme.html and remove the wp_generator action.
"""
from __future__ import annotations

import re

import httpx

from ..http import Client
from ..models import Finding

GENERATOR_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)',
    re.IGNORECASE,
)
GENERATOR_FEED = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>", re.IGNORECASE
)
README_VERSION = re.compile(r"Version\s+([0-9.]+)", re.IGNORECASE)


_PRE_RELEASE_TAG = re.compile(
    r"^(\d+(?:\.\d+)*)[-.]?(?:alpha|beta|rc|a|b)[-.]?\d*(?:[-.].*)?$", re.IGNORECASE
)


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Sortable key for a WordPress version string.

    Mirrors db.ver_lt semantics (self-contained on purpose): numeric components
    are kept and padded to 4 so 6.5 == 6.5.0, and a pre-release suffix
    (`6.5-rc1`, `6.5-beta2`) sorts BELOW the same release but ABOVE the
    previous one: 6.4.3 < 6.5-rc1 < 6.5. The last tuple slot is the release
    flag (0 = release, -1 = pre-release). Returns () when `v` is not a version.
    """
    v = (v or "").strip()
    m = _PRE_RELEASE_TAG.match(v)
    base = m.group(1) if m else v
    try:
        parts = [int(p) for p in base.split(".") if p != ""]
    except ValueError:
        return ()
    if not parts:
        return ()
    while len(parts) < 4:
        parts.append(0)
    parts.append(-1 if m else 0)
    return tuple(parts)


async def _latest_wp_version() -> str | None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get("https://api.wordpress.org/core/version-check/1.7/")
            r.raise_for_status()
            offers = r.json().get("offers") or []
            for o in offers:
                if o.get("response") == "upgrade" or o.get("current"):
                    return o.get("current")
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    version: str | None = None
    source: str = ""

    # 1. homepage <meta generator>
    step("fetching / for <meta generator>...")
    home = await client.get("/")
    if home is not None and home.status_code == 200:
        m = GENERATOR_META.search(home.text or "")
        if m:
            version = m.group(1)
            source = "meta generator tag on /"

    # 2. RSS feed <generator>
    if not version:
        step("fetching /feed/ for <generator>...")
        feed = await client.get("/feed/")
        if feed is not None and feed.status_code == 200:
            m = GENERATOR_FEED.search(feed.text or "")
            if m:
                version = m.group(1)
                source = "/feed/ <generator>"

    # 3. readme.html
    step("probing /readme.html...")
    readme = await client.get("/readme.html")
    if readme is not None and readme.status_code == 200 and "WordPress" in (readme.text or ""):
        m = README_VERSION.search(readme.text)
        if m:
            if not version:
                version = m.group(1)
                source = "/readme.html"
            findings.append(
                Finding(
                    severity="medium",
                    title="readme.html is publicly accessible",
                    evidence=f"GET /readme.html → 200, leaks WordPress version {m.group(1)}",
                    remediation="Delete /readme.html or block it with a server-level deny rule. It serves no purpose in production and broadcasts your WP version.",
                    url=client.url("/readme.html"),
                )
            )

    # Store version in shared context for other checks
    ctx["shared"]["wp_version"] = version

    if not version:
        # No leak detected — that's actually a good thing. Surface as info.
        findings.append(
            Finding(
                severity="info",
                title="WordPress core version not disclosed via common channels",
                evidence="No <meta generator>, /readme.html, or /feed/ version leak detected.",
                remediation="No action needed. Continue suppressing WP version disclosure.",
                url=ctx["target"],
            )
        )
        return findings

    step("looking up latest WP version from api.wordpress.org...")
    latest = await _latest_wp_version()
    if latest and _ver_tuple(version) and _ver_tuple(latest):
        if _ver_tuple(version) < _ver_tuple(latest):
            findings.append(
                Finding(
                    severity="high",
                    title=f"WordPress core is outdated: {version} (latest: {latest})",
                    evidence=f"Detected version {version} via {source}; latest stable is {latest}.",
                    remediation=f"Update WordPress core to {latest} via Dashboard → Updates. Test in staging if you run heavy plugins.",
                    url=ctx["target"],
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    title=f"WordPress core is up to date ({version})",
                    evidence=f"Detected {version} via {source}; latest is {latest}.",
                    remediation="No action needed.",
                    url=ctx["target"],
                )
            )
    else:
        findings.append(
            Finding(
                severity="medium",
                title=f"WordPress version {version} disclosed",
                evidence=f"Source: {source}. Could not reach api.wordpress.org to compare.",
                remediation="Suppress version disclosure: remove the generator meta with `remove_action('wp_head','wp_generator')` and consider deleting /readme.html.",
                url=ctx["target"],
            )
        )

    return findings
