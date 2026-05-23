"""#15 (from nuclei) — auto-scan mode (template auto-selection).

Picks templates from ~/.wpsecscan/templates/ based on the initial target
fingerprint. If the target is WordPress, prefer templates tagged `wordpress`;
if it's Apache, prefer `apache`; etc. Drops irrelevant templates entirely so
the scan doesn't waste time.

Used by the existing `yaml_templates` check when `ctx["auto_scan"]` is set.
"""
from __future__ import annotations

import re
from pathlib import Path

# Conservative tech → priority-tag mapping
TECH_TAG_PRIORITY = {
    "wordpress": ["wordpress", "wp", "wp-plugin", "cms"],
    "woocommerce": ["woocommerce", "wordpress", "wp-plugin", "cms"],
    "drupal": ["drupal", "cms"],
    "joomla": ["joomla", "cms"],
    "magento": ["magento", "cms"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis", "windows"],
    "php": ["php"],
    "node": ["node", "nodejs"],
}


def detect_tech(ctx: dict) -> list[str]:
    """Inspect ctx['shared'] for tech fingerprints. Returns matched keys.

    Falls back to 'wordpress' since we're a WP scanner — that's the
    expected default tag for shipped/community templates."""
    shared = ctx.get("shared") or {}
    techs: set[str] = set()
    # WAF check populates shared['waf']; not useful here. Core check populates
    # shared['core_version']; presence means WP.
    if shared.get("core_version") or shared.get("plugins"):
        techs.add("wordpress")
    # The favicon hash check populates shared['favicon_tech']
    fav_tech = (shared.get("favicon_tech") or "").lower()
    if "wordpress" in fav_tech:
        techs.add("wordpress")
    if "woocommerce" in str(shared.get("plugins") or []).lower():
        techs.add("woocommerce")
    return sorted(techs) if techs else ["wordpress"]


def filter_templates(templates: list, ctx: dict) -> list:
    """Return only templates whose `info.tags` overlap with detected tech."""
    techs = detect_tech(ctx)
    wanted_tags: set[str] = set()
    for t in techs:
        wanted_tags.update(TECH_TAG_PRIORITY.get(t, []))
    out = []
    for tmpl in templates:
        info = tmpl.get("info") or {}
        raw_tags = info.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [s.strip() for s in raw_tags.split(",")]
        if any(t in wanted_tags for t in raw_tags):
            out.append(tmpl)
    return out
