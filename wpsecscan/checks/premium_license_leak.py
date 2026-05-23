"""#7 (from wpscan) — premium plugin license-key leak.

Several commercial WP plugins (Elementor Pro, Yoast Premium, WP Rocket,
Gravity Forms, Beaver Builder, Easy Digital Downloads, WPMU DEV) store
their license key inside a settings file that occasionally gets bundled
into the page's enqueued JS / CSS / HTML output. When that happens, the
license key is exposed to every visitor and an attacker can use it on
their own install to get free updates / pirate the plugin.

We probe the homepage HTML + common admin-ajax enqueue paths for license-key
patterns (`license_key=`, `pro_license=`, `_license_status`, etc.).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# (pattern, what-it-belongs-to)
LICENSE_PATTERNS = (
    (re.compile(r'"license_key"\s*:\s*"([A-Z0-9-]{20,64})"'),  "generic plugin license_key field"),
    (re.compile(r'pro_license[\'"]\s*[:=]\s*[\'"]([A-Z0-9-]{20,64})'), "Pro plugin license"),
    (re.compile(r'_license_status[\'"]\s*[:=]\s*[\'"]([a-z_]+)'), "license status field (may indicate leak proximity)"),
    (re.compile(r'elementor_pro[_-]license[_-]key[\'"]?\s*[:=]\s*[\'"]?([A-Z0-9-]{20,64})'), "Elementor Pro"),
    (re.compile(r'rocket[_-]license[_-]key[\'"]?\s*[:=]\s*[\'"]?([A-Z0-9-]{20,64})'), "WP Rocket"),
    (re.compile(r'gf[_-]license[_-]key[\'"]?\s*[:=]\s*[\'"]?([A-Z0-9-]{20,64})'), "Gravity Forms"),
    (re.compile(r'beaver[_-]builder[_-]license[\'"]?\s*[:=]\s*[\'"]?([A-Z0-9-]{20,64})'), "Beaver Builder"),
    (re.compile(r'wpmudev[_-]apikey[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9]{32,64})'), "WPMU DEV API key"),
    (re.compile(r'edd[_-]license[_-]key[\'"]?\s*[:=]\s*[\'"]?([A-Z0-9-]{20,64})'), "Easy Digital Downloads"),
)
SCAN_PATHS = ("/", "/?page_id=2", "/wp-admin/admin-ajax.php?action=heartbeat")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    hits: list[tuple[str, str, str, str]] = []  # (plugin, path, value_preview, value_full)
    for path in SCAN_PATHS:
        step(f"premium-license probe {path}...")
        r = await client.get(path)
        if r is None:
            continue
        body = (r.text or "")[:200_000]  # cap to 200KB so a runaway page doesn't OOM us
        for pat, label in LICENSE_PATTERNS:
            for m in pat.finditer(body):
                val = m.group(1)
                if len(val) < 20:
                    continue
                hits.append((label, path, val[:6] + "..." + val[-4:], val))

    if not hits:
        findings.append(Finding(
            severity="info",
            title="Premium plugin license-key scan — clean",
            evidence=(f"Scanned {len(SCAN_PATHS)} URL(s) against {len(LICENSE_PATTERNS)} known "
                       f"premium-plugin license patterns. No leakage."),
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Dedupe by full value
    seen = set()
    deduped = []
    for label, path, preview, val in hits:
        if val in seen:
            continue
        seen.add(val)
        deduped.append((label, path, preview))

    findings.append(Finding(
        severity="critical",
        title=f"Premium plugin license key leaked in page HTML ({len(deduped)} key(s))",
        evidence="\n".join(f"  - {label} at {path}: {preview}" for label, path, preview in deduped) + (
            "\n\nA leaked license key allows pirates to activate the plugin on their own "
            "install + receive automatic updates as if they had paid. The plugin vendor's "
            "license-server will eventually block the key, but until then the leaker pays "
            "for someone else's installs. Some vendors also use the license key as an auth "
            "token for support tickets — leaks can let third parties open tickets in your name."
        ),
        remediation=(
            "1. Rotate the affected license keys in the plugin vendor's account dashboard.\n"
            "2. Find the offending setting in wp-admin and remove it from any front-end "
            "enqueued scripts (search the codebase for `wp_localize_script` calls that "
            "pass the license value).\n"
            "3. The plugin author should never have echoed the license to the public side — "
            "if it's a plugin you control, fix the leak upstream; if it's a third-party "
            "plugin, file a security report with the vendor."
        ),
        url=ctx["target"],
    ))
    return findings
