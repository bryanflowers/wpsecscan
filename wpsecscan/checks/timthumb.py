"""#1 (from wpscan) — timthumb.php detection + version-banner CVE matching.

timthumb is a long-deprecated image-thumbnail PHP library shipped with many
old free WordPress themes. Versions before 2.8.14 had remote-file-include
bugs (CVE-2011-4106, CVE-2014-4663) that gave attackers RCE. Despite being
patched in 2014, it's still found on ~3-5% of WP sites in the wild because
the theme bundles haven't been updated.

We probe 8 common timthumb paths and inspect the banner comment for the
version string.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


PROBE_PATHS = (
    "/wp-content/themes/timthumb.php",
    "/wp-content/scripts/timthumb.php",
    "/wp-content/plugins/timthumb.php",
    "/thumb.php",
    "/timthumb.php",
    "/wp-content/themes/{theme}/timthumb.php",
    "/wp-content/themes/{theme}/scripts/timthumb.php",
    "/wp-content/themes/{theme}/includes/timthumb.php",
)
VERSION_RE = re.compile(r"version\s*=\s*['\"]([\d.]+)['\"]|VERSION\s*=\s*['\"]([\d.]+)['\"]|TimThumb\s+([\d.]+)", re.IGNORECASE)
LAST_VULN_VERSION = "2.8.13"  # patched in 2.8.14


def _vuln_against(version: str, vuln_max: str) -> bool:
    try:
        v = tuple(int(p) for p in version.split("."))
        m = tuple(int(p) for p in vuln_max.split("."))
        return v <= m
    except (ValueError, AttributeError):
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # If themes check populated ctx['shared']['themes'], use those slugs too
    shared = ctx.get("shared") or {}
    themes = shared.get("themes") or []
    theme_slugs = [t.get("slug") for t in themes if isinstance(t, dict) and t.get("slug")]

    paths_to_try: list[str] = []
    for p in PROBE_PATHS:
        if "{theme}" in p:
            for slug in theme_slugs[:5]:  # cap to avoid request explosion
                paths_to_try.append(p.format(theme=slug))
        else:
            paths_to_try.append(p)

    hits: list[tuple[str, str | None]] = []  # (path, version or None)
    for path in paths_to_try:
        step(f"timthumb probe {path}...")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        body = (r.text or "")[:5000]
        if "timthumb" not in body.lower() and "tim thumb" not in body.lower():
            continue
        m = VERSION_RE.search(body)
        version = None
        if m:
            version = next((g for g in m.groups() if g), None)
        hits.append((path, version))

    if not hits:
        findings.append(Finding(
            severity="info",
            title="No timthumb.php found",
            evidence=f"Probed {len(paths_to_try)} common timthumb paths; none returned a timthumb-shaped response.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    for path, version in hits:
        sev = "info"
        title = f"timthumb.php reachable at {path}"
        if version:
            if _vuln_against(version, LAST_VULN_VERSION):
                sev = "critical"
                title = f"VULNERABLE timthumb {version} at {path} — CVE-2011-4106 / CVE-2014-4663 (RCE)"
            else:
                sev = "low"
                title = f"timthumb {version} at {path} (patched version, but exposing image-resize endpoints is still attack surface)"
        findings.append(Finding(
            severity=sev,
            title=title,
            evidence=(
                f"GET {path} -> 200 OK, body contains a timthumb banner"
                + (f"; version {version}" if version else "; no version string detected") + "."
            ),
            remediation=(
                "Remove timthumb.php — it's been obsolete since 2014 and built-in WP image "
                "functions (`wp_get_attachment_image_src` + the media library) cover every "
                "use case. If the theme depends on it, switch to a modern theme."
            ),
            url=ctx["target"] + path,
        ))
    return findings
