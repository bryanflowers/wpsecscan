"""Sitemap-driven CVE probe.

Pulls `/sitemap.xml` and `/wp-sitemap.xml`, extracts every URL, then probes
each URL against a small catalog of known-vulnerable WP URL patterns:
  - `?elementor-action=...` — Essential Addons / Elementor unauth-vuln
  - `?wc-ajax=...` — WooCommerce AJAX surface
  - `?action=astoundify_...` — Astoundify framework
  - `?post_type=shop_order` admin actions (auth required)
  - `?id=N&controller=...` legacy plugin routers

Surfaces URLs that match one of these patterns AND respond differently than
their bare equivalent (status delta, body delta).
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from ..http import Client
from ..models import Finding

SITEMAP_PATHS = ("/sitemap.xml", "/wp-sitemap.xml", "/sitemap_index.xml")

# Patterns of interest — append these to discovered URLs and check for delta.
VULN_QUERY_PATTERNS = (
    ("elementor-action", "elementor_action_test_smtp", "Elementor / Essential Addons action vector"),
    ("wc-ajax", "checkout", "WooCommerce AJAX vector"),
    ("astoundify_action", "test", "Astoundify framework action"),
    ("controller", "..%2f..%2fwp-config.php", "Legacy plugin router path-traversal"),
    ("action", "give_donation_form_load", "GiveWP donation form action"),
)


def _extract_urls_from_sitemap(xml_text: str, base_target: str) -> list[str]:
    """Extract loc URLs from a sitemap (sitemap-index OR urlset)."""
    out: list[str] = []
    try:
        # Strip namespace for robust parsing
        cleaned = re.sub(r'\sxmlns="[^"]+"', "", xml_text, count=1)
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return out
    for loc in root.iter("loc"):
        url = (loc.text or "").strip()
        if url and (url.startswith(base_target) or url.startswith("/")):
            out.append(url)
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    # 1. Find any working sitemap
    all_urls: set[str] = set()
    sitemap_paths_found: list[str] = []
    for path in SITEMAP_PATHS:
        step(f"fetching {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        sitemap_paths_found.append(path)
        # Sitemap index may reference child sitemaps — follow one level.
        urls = _extract_urls_from_sitemap(r.text, target)
        # If these end in .xml, they're child sitemaps
        child_maps = [u for u in urls if u.endswith(".xml")]
        page_urls = [u for u in urls if not u.endswith(".xml")]
        all_urls.update(page_urls)
        # Follow first 3 child sitemaps max
        for cm in child_maps[:3]:
            child_path = cm.replace(target, "") if cm.startswith(target) else cm
            step(f"following child sitemap {child_path}...")
            r2 = await client.get(child_path)
            if r2 is not None and r2.status_code == 200 and r2.text:
                all_urls.update(_extract_urls_from_sitemap(r2.text, target))

    if not sitemap_paths_found:
        findings.append(
            Finding(
                severity="info",
                title="No sitemap found — sitemap-driven CVE probe skipped",
                evidence=f"Tried: {', '.join(SITEMAP_PATHS)}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    if not all_urls:
        findings.append(
            Finding(
                severity="info",
                title=f"Sitemap(s) {', '.join(sitemap_paths_found)} are empty",
                evidence="The sitemap responded with 200 but contained no <loc> elements.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # 2. Probe each URL with vuln patterns. Cap at 25 sitemap URLs to bound the work.
    probe_urls = list(all_urls)[:25]
    matches: list[tuple[str, str, str, int]] = []  # (url, pattern, label, status)
    for url in probe_urls:
        # Make URL relative for client.get()
        rel = url.replace(target, "") if url.startswith(target) else url
        if not rel.startswith("/"):
            continue
        for param, value, label in VULN_QUERY_PATTERNS:
            step(f"probing {rel[:50]} with ?{param}=...")
            r = await client.get(rel, params={param: value})
            if r is None:
                continue
            # Look for "different response than baseline" — status 200 with NON-default
            # body (i.e. not a generic 404) OR an explicit 500 are interesting.
            if r.status_code == 500:
                matches.append((rel, param, label, 500))
            elif r.status_code == 200 and r.content and len(r.content) > 100:
                # Compare against the bare URL
                r0 = await client.get(rel)
                if r0 is not None and abs(len(r.content) - len(r0.content or b"")) > 200:
                    matches.append((rel, param, label, 200))

    if not matches:
        findings.append(
            Finding(
                severity="info",
                title=f"Sitemap-driven CVE probe clean ({len(probe_urls)} URLs tested)",
                evidence=f"Probed {len(probe_urls)} sitemap URLs against {len(VULN_QUERY_PATTERNS)} known vuln-pattern params; no delta responses.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for url, param, label, status in matches[:10]:
        findings.append(
            Finding(
                severity="medium",
                title=f"Sitemap URL responds to vuln pattern: {url}?{param}=...",
                evidence=(
                    f"GET {url}?{param}=<test> -> HTTP {status} with content delta vs baseline\n"
                    f"Suspect vector: {label}"
                ),
                remediation=(
                    "Investigate the plugin owning this URL. The fact that adding the parameter changes "
                    "the response means there's a code path that consumes the parameter — verify it's "
                    "sanitised. Cross-reference the plugin slug with Wordfence/Patchstack CVE DBs."
                ),
                url=client.url(url),
            )
        )
    return findings
