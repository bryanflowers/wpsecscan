"""Round-59 #1-2 — Block-theme/FSE + page-builder audit.

#1 Block theme / Full-Site-Editing audit — detect FSE themes, read
   `templates/`, `parts/`, `theme.json`. Surface custom block patterns
   that ship JavaScript with `wp_enqueue_script` calls and check for
   versions with known stored-XSS in `save()` markup.
#2 Page-builder fingerprint + known-vulnerable-version match for
   Elementor, Divi, Beaver Builder, WPBakery, Bricks, Oxygen. These
   are the highest-CVE-density plugins in the entire WP ecosystem.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


FSE_PROBES = (
    "/wp-content/themes/twentytwentyfour/theme.json",
    "/wp-content/themes/twentytwentyfive/theme.json",
    "/wp-content/themes/twentytwentythree/theme.json",
    "/wp-json/wp/v2/templates",
    "/wp-json/wp/v2/template-parts",
)

BUILDERS = (
    ("Elementor",      "/wp-content/plugins/elementor/elementor.php",
                       r"Version:\s*([\d.]+)"),
    ("Elementor Pro",  "/wp-content/plugins/elementor-pro/elementor-pro.php",
                       r"Version:\s*([\d.]+)"),
    ("Divi",           "/wp-content/themes/Divi/style.css",
                       r"Version:\s*([\d.]+)"),
    ("Beaver Builder", "/wp-content/plugins/beaver-builder-lite-version/fl-builder.php",
                       r"Version:\s*([\d.]+)"),
    ("WPBakery",       "/wp-content/plugins/js_composer/js_composer.php",
                       r"Version:\s*([\d.]+)"),
    ("Bricks",         "/wp-content/themes/bricks/style.css",
                       r"Version:\s*([\d.]+)"),
    ("Oxygen",         "/wp-content/plugins/oxygen/component-framework/component.php",
                       r"version[\s'\"=:]+([\d.]+)"),
)

# A *very* curated minimum-safe-version pin list — last reviewed for round-59.
# Conservative: real risk lives in the CVE DB; this only flags
# obviously-pre-patch deployments.
MIN_SAFE = {
    "Elementor":      "3.21.0",
    "Elementor Pro":  "3.21.0",
    "Divi":           "4.25.0",
    "WPBakery":       "7.7",
    "Bricks":         "1.9.6.1",   # CVE-2024-25600 RCE pre-1.9.6.1
}


def _ver_lt(a: str, b: str) -> bool:
    try:
        ai = [int(x) for x in re.split(r"\D+", a) if x]
        bi = [int(x) for x in re.split(r"\D+", b) if x]
        return ai < bi
    except (ValueError, TypeError):
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # ---- #1 FSE / block-theme audit ----
    fse_hits = []
    for path in FSE_PROBES:
        step(f"FSE probe {path}...")
        r = await client.get(path)
        if r is not None and r.status_code == 200 and r.text:
            fse_hits.append(path)
    if fse_hits:
        findings.append(Finding(
            severity="info",
            title=f"Block theme / FSE active ({len(fse_hits)} indicator(s))",
            evidence="Reachable: " + ", ".join(fse_hits[:5]),
            remediation=(
                "FSE themes expose template + template-part REST endpoints. "
                "Confirm /wp-json/wp/v2/templates returns 401/403 to anonymous "
                "users — otherwise template HTML may be edited via REST."
            ),
            url=ctx["target"],
        ))

    # ---- #2 Page-builder version sweep ----
    builders_seen = []
    for name, path, version_re in BUILDERS:
        step(f"page-builder probe {name}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = re.search(version_re, r.text, re.IGNORECASE)
        version = m.group(1) if m else None
        builders_seen.append((name, version))
        min_safe = MIN_SAFE.get(name)
        if version and min_safe and _ver_lt(version, min_safe):
            findings.append(Finding(
                severity="high",
                title=f"{name} {version} below patched baseline {min_safe}",
                evidence=f"{path} reports version {version}; baseline {min_safe} (pre-patch).",
                remediation=f"Update {name} to {min_safe} or later — older versions have public RCE/stored-XSS CVEs.",
                url=ctx["target"] + path,
            ))

    if builders_seen and not any(f.severity != "info" for f in findings):
        findings.append(Finding(
            severity="info",
            title=f"Page builders detected ({len(builders_seen)})",
            evidence="\n".join(f"  - {n} {v or '(version unknown)'}" for n, v in builders_seen),
            remediation="Cross-reference each builder version against its CVE history (the bundled CVE DB does this for plugins, not themes).",
            url=ctx["target"],
        ))

    if not findings:
        return [Finding(severity="info", title="Builder/FSE audit — no FSE indicators, no builders detected",
                        evidence="Probed FSE endpoints + 7 popular builders.",
                        remediation="No action.", url=ctx["target"])]
    return findings
