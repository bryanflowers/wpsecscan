"""Detect /wp-content/object-cache.php drop-in and fingerprint the plugin.

WordPress drop-ins live in /wp-content/ and are loaded before any plugin
or theme. They're not listed in /wp/v2/plugins, so plugin-enumeration
misses them entirely. The most common drop-in is `object-cache.php`,
installed by Redis Object Cache, W3 Total Cache, LiteSpeed Cache,
WP Redis, etc. Each has had CVEs.

We probe the file existence (200 with text/plain or text/x-php is the
common signal), read the first 2 KB to fingerprint the installer, and
emit a finding the user can cross-reference against the CVE DB.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_VENDOR_PATTERNS = (
    ("Redis Object Cache",  re.compile(r"@package\s+Redis_Object_Cache|class\s+WP_Object_Cache\s*{.*Redis", re.IGNORECASE | re.DOTALL)),
    ("W3 Total Cache",      re.compile(r"w3tc|W3_Object_Cache", re.IGNORECASE)),
    ("LiteSpeed Cache",     re.compile(r"litespeed[-_]cache|LiteSpeed\\Cache", re.IGNORECASE)),
    ("WP Redis",            re.compile(r"plugins/wp-redis|wp_redis", re.IGNORECASE)),
    ("Memcached Object Cache", re.compile(r"memcached", re.IGNORECASE)),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("probing /wp-content/object-cache.php existence...")
    r = await client.get("/wp-content/object-cache.php")
    if r is None or r.status_code != 200:
        return findings
    body = (r.text or "")[:2048]
    # Defence: WordPress's PHP files normally don't return raw source to the
    # public, so a 200 with parseable content is itself somewhat unusual.
    # We only continue if the response contains '<?php' (PHP source) or
    # other strong PHP-source markers — otherwise it's a soft-404 or proxy
    # rewrite returning the homepage.
    if "<?php" not in body and "object-cache" not in body.lower():
        return findings
    vendor = "unidentified vendor"
    for name, rx in _VENDOR_PATTERNS:
        if rx.search(body):
            vendor = name
            break
    findings.append(Finding(
        severity="high",
        title=f"/wp-content/object-cache.php drop-in source publicly readable ({vendor})",
        evidence=(
            f"GET /wp-content/object-cache.php → HTTP 200 with PHP source content.\n"
            f"Identified vendor: {vendor}\n\n"
            "This is doubly problematic:\n"
            "1. The drop-in's source code leaks (the user-installed cache plugin's "
            "version + structure → CVE matching is trivial).\n"
            "2. The web server is serving raw .php source for at least this file — "
            "indicates PHP-FPM / FastCGI is not configured to handle the path, OR "
            "a server-misconfig is bypassing PHP execution. Other .php files in "
            "/wp-content/ may be affected the same way."
        ),
        remediation=(
            "1. Cross-reference the identified vendor against the CVE database — "
            f"`wpsecscan` flags known CVEs separately, but {vendor} drop-ins "
            "specifically have had auth-bypass and cache-poisoning issues.\n"
            "2. Investigate why .php is being served as text. Likely: PHP-FPM "
            "handler missing or `AddType application/x-httpd-php` not applied to "
            "/wp-content/. Test with `curl -I` against any other .php file under "
            "/wp-content/ to scope the misconfig.\n"
            "3. If the drop-in isn't actively in use, delete it. Drop-ins persist "
            "after the parent plugin is removed."
        ),
        url=client.url("/wp-content/object-cache.php"),
        extra={"vendor": vendor},
    ))
    return findings
