"""Item #18 — fingerprint page-builders + cross-reference known CVE families.

The popular WordPress page-builders share a pattern: they expose front-end
HTML markers, ship deep frontend JS APIs, and each has had at least one
critical RCE (Bricks CVE-2024-25600 unauth RCE; Beaver had a 2023 stored-
XSS family; Divi had the et_pb_send_to_friend RCE in 2024; WPBakery had
multiple stored-XSS issues).

This check is detection-only. We fingerprint via HTML markers and report
the builder + a hint at currently-known CVE families. We deliberately do
NOT version-detect or fire an exploit — the `plugin_cves` check pulls
the canonical CVE feed; we just make sure these builders are visible to
that pipeline even when they're served by a theme (Bricks, Divi) rather
than installed as a plugin.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# Each entry: (display_name, HTML-regex marker, known CVE families summary).
# The regex matches the most stable marker each builder leaves in front-end
# HTML; it deliberately does NOT match the dashboard.
_BUILDERS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("Bricks Builder",
     re.compile(r'(?:<meta[^>]+content="Bricks[^"]*"|/bricks-builder/|class="brxe-)',
                  re.IGNORECASE),
     "CVE-2024-25600 (unauth RCE via /wp-json/bricks/v1/render_element). "
     "Ensure Bricks ≥ 1.9.6.1."),
    ("Beaver Builder",
     re.compile(r'(?:fl-builder-content|fl-page-content|/beaver-builder-lite-version/|/bb-plugin/)',
                  re.IGNORECASE),
     "Stored XSS via Heading module before 2.7.4 (CVE-2024-3925-class). "
     "Ensure Beaver Builder ≥ 2.7.4."),
    ("Divi (Elegant Themes)",
     re.compile(r'(?:class="et_pb_|/themes/Divi/|et_monarch|divi-theme-)',
                  re.IGNORECASE),
     "et_pb_send_to_friend reflected-XSS (CVE-2024-3429-class) and "
     "unauth-arbitrary-file-write via shortcode pre-Divi 4.x. "
     "Ensure Divi ≥ 4.27."),
    ("WPBakery (Visual Composer)",
     re.compile(r'(?:js_composer|vc_row\b|wpb_(?:row|column)|vc_custom_)',
                  re.IGNORECASE),
     "Multiple stored-XSS in custom-element rendering (CVE-2023-46139-class). "
     "Ensure WPBakery ≥ 7.7."),
    ("Oxygen Builder",
     re.compile(r'(?:oxygen-builder|/oxygen/|ct_section\b|ct_div_block\b)',
                  re.IGNORECASE),
     "SSRF + auth-bypass in admin REST routes (CVE-2024-1071-class). "
     "Ensure Oxygen Builder ≥ 4.8.1."),
    ("Brizy Builder",
     re.compile(r'(?:brizy-content|/brizy/|class="brz-)',
                  re.IGNORECASE),
     "Brizy versions before 2.5.0 had a public template-save endpoint. "
     "Ensure Brizy ≥ 2.5.0."),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching / for page-builder fingerprinting...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    body = r.text[:200_000]

    seen: list[tuple[str, str]] = []  # (display_name, cve_summary)
    for name, marker, cves in _BUILDERS:
        if marker.search(body):
            seen.append((name, cves))

    if not seen:
        findings.append(Finding(
            severity="info",
            title="Page-builder fingerprint — none detected",
            evidence=f"Scanned / for markers from {len(_BUILDERS)} known builders.",
            remediation="No action needed.",
            url=ctx["target"],
        ))
        return findings

    for name, cves in seen:
        findings.append(Finding(
            severity="low",
            title=f"Page builder detected: {name}",
            evidence=(
                f"HTML markers consistent with {name} are present on the homepage.\n\n"
                f"Known CVE families to verify against:\n  {cves}"
            ),
            remediation=(
                f"Verify {name} is fully patched. Cross-reference the running "
                "version against wpscan.com / patchstack.com — `wpsecscan` "
                "pulls these into the plugin_cves check when a version "
                "string is visible. If only a theme-bundled builder (Bricks "
                "or Divi), check the theme version explicitly: WP admin → "
                "Appearance → Themes → click the active theme."
            ),
            url=ctx["target"],
            extra={"builder": name},
        ))
    return findings
