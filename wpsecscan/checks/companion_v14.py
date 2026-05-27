"""B38-B45 (v2.7.0) — consumers of the companion plugin v1.4 endpoints.

No-op silently when --companion-token isn't set.

  B38 /plugin-license-keys     — confirm legitimate plugin licensing
  B40 /active-network-requests — outbound-traffic anomalies
  B41 /page-cache-info         — cache plugin + logged-in caching leak
  B43 /database-encoding       — non-utf8mb4 tables (homograph SQLi)
  B44 /customizer-bookmarks    — XSS in theme_mod values
  B45 /widget-block-html       — XSS in block widgets
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


async def _hit(base: str, path: str, token: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(
                base.rstrip("/") + path,
                headers={"X-WPSecScan-Token": token,
                          "User-Agent": "WPSecScan/companion-v14"},
            )
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return None
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    token = ctx.get("companion_token")
    if not token:
        return findings

    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"

    # B38 — plugin-license-keys (info)
    step("companion v1.4: plugin-license-keys")
    lic = await _hit(base, "/wp-json/wpsecscan/v1/plugin-license-keys", token)
    if lic and lic.get("count", 0) > 0:
        empties = [opt for opt in lic.get("license_options", []) if opt.get("looks_empty")]
        if empties:
            findings.append(Finding(
                severity="low",
                title=f"Plugins with empty license-key options: {len(empties)}",
                evidence="Plugin license-key options exist but are empty:\n  "
                + "\n  ".join(e["option_name"] for e in empties[:10]),
                remediation="Either deactivate the plugin or enter a valid license. "
                              "Unlicensed-plugin behaviour can include skipped security updates.",
                url=client.url("/wp-admin/plugins.php"),
                extra={"empty_count": len(empties)},
            ))

    # B40 — active-network-requests (medium if >100/day)
    step("companion v1.4: active-network-requests")
    out = await _hit(base, "/wp-json/wpsecscan/v1/active-network-requests", token)
    if out:
        n = int(out.get("count_24h", 0))
        if n > 100:
            findings.append(Finding(
                severity="medium",
                title=f"Outbound wp_remote_* traffic high: {n} requests in 24h",
                evidence=(
                    f"Last-24h outbound HTTP requests from wp_remote_*: {n}.\n"
                    "Top hosts: " + ", ".join(f"{h}={c}" for h, c in
                                                (out.get("top_hosts") or {}).items()) + "\n"
                    "High outbound volume is often a compromise indicator "
                    "(crypto-miner / spam-mailer / data exfil)."
                ),
                remediation=(
                    "1. Audit the top-hosts list — anything unfamiliar is suspect.\n"
                    "2. Block unknown outbound hosts at the firewall.\n"
                    "3. Audit recently-installed plugins; the outbound traffic\n"
                    "   originates from a plugin's wp_remote_* calls."
                ),
                url=client.url("/wp-admin/"),
                extra={"count_24h": n, "top_hosts": out.get("top_hosts")},
            ))

    # B41 — page-cache-info (high when logged-in users cached)
    step("companion v1.4: page-cache-info")
    pc = await _hit(base, "/wp-json/wpsecscan/v1/page-cache-info", token)
    if pc:
        plugins = pc.get("plugins_detected", [])
        size_gb = pc.get("cache_size_bytes", 0) / (1024 ** 3)
        if plugins:
            findings.append(Finding(
                severity="info",
                title=f"Page-cache plugin(s) active: {', '.join(plugins)}",
                evidence=(
                    f"Detected: {', '.join(plugins)}\n"
                    f"Cache dir: {pc.get('cache_dir')}\n"
                    f"Cache size: {size_gb:.2f} GiB ({pc.get('cache_file_count', 0)} files)"
                ),
                remediation=(
                    "Confirm logged-in users are NOT served from the page cache "
                    "(privacy leak: another user can see the previous user's "
                    "personalised page). Audit the cache plugin's 'cache-for-"
                    "logged-in-users' setting (should be OFF)."
                ),
                url=client.url("/wp-admin/"),
                extra={"plugins": plugins, "size_bytes": pc.get("cache_size_bytes")},
            ))

    # B43 — database-encoding (medium per non-utf8mb4 table)
    step("companion v1.4: database-encoding")
    enc = await _hit(base, "/wp-json/wpsecscan/v1/database-encoding", token)
    if enc and enc.get("mismatched_count", 0) > 0:
        bad = enc.get("non_utf8mb4_tables", [])
        findings.append(Finding(
            severity="medium",
            title=f"DB tables not using utf8mb4: {enc['mismatched_count']}",
            evidence=(
                f"Connection charset: {enc.get('connection_charset')}\n"
                f"Non-utf8mb4 tables ({len(bad)}):\n  "
                + "\n  ".join(f"{t['table']} ({t['collation']})" for t in bad[:15])
            ),
            remediation=(
                "Mixed charset/collation across tables enables emoji-homograph "
                "SQLi (single byte collation accepts a multibyte injection that "
                "later compares-equal). Convert each table to utf8mb4 with:\n"
                "  ALTER TABLE wp_xxx CONVERT TO CHARACTER SET utf8mb4 "
                "COLLATE utf8mb4_unicode_520_ci;\n"
                "Run wpsecscan/wpsecscan-companion's DB convert helper for safety."
            ),
            url=client.url("/wp-admin/"),
            extra={"bad_tables": [t["table"] for t in bad]},
        ))

    # B44 — customizer-bookmarks (high if XSS payload present)
    step("companion v1.4: customizer-bookmarks")
    cb = await _hit(base, "/wp-json/wpsecscan/v1/customizer-bookmarks", token)
    if cb and cb.get("count", 0) > 0:
        for risky in cb.get("risky_modifiers", []):
            findings.append(Finding(
                severity="high",
                title=f"Customizer modifier contains script/iframe payload: {risky['key']}",
                evidence=(
                    f"Theme: {cb.get('theme')}\n"
                    f"theme_mod key: {risky['key']}\n"
                    f"Value (truncated):\n  {risky['value_excerpt']}"
                ),
                remediation=(
                    "1. Open Appearance → Customize and remove the offending\n"
                    "   value (or replace it with a clean one).\n"
                    "2. If the value wasn't set by an admin, treat as a\n"
                    "   compromise — audit recent wp-admin activity.\n"
                    "3. Add the relevant theme_mod_* filter to escape any\n"
                    "   future user-supplied value before rendering."
                ),
                url=client.url("/wp-admin/customize.php"),
                extra={"theme_mod_key": risky["key"]},
            ))

    # B45 — widget-block-html
    step("companion v1.4: widget-block-html")
    wb = await _hit(base, "/wp-json/wpsecscan/v1/widget-block-html", token)
    if wb and wb.get("count", 0) > 0:
        for risky in wb.get("risky_widgets", []):
            findings.append(Finding(
                severity="high",
                title=f"Widget contains raw script/iframe: {risky['option_name']}",
                evidence=(
                    f"wp_options.option_name: {risky['option_name']}\n"
                    f"Value (truncated):\n  {risky['value_excerpt']}"
                ),
                remediation=(
                    "Open /wp-admin/widgets.php and remove the offending widget,\n"
                    "or replace its HTML with a sanitized version. If this widget\n"
                    "wasn't placed by an admin, treat as compromise."
                ),
                url=client.url("/wp-admin/widgets.php"),
                extra={"option_name": risky["option_name"]},
            ))

    return findings
