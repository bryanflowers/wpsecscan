"""robots.txt + sitemap.xml intelligence.

Beyond just fetching them, mine them for:
  - Admin paths and staging URLs leaked via Disallow:
  - All discovered URLs via sitemap (great for finding admin-* pages,
    abandoned subdomains, leaked draft posts, etc.)
  - Sitemap that exposes media uploads, plugin upload paths, etc.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

DISALLOW_RE = re.compile(r"^\s*disallow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
SITEMAP_RE  = re.compile(r"^\s*sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
URL_TAG_RE  = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

SENSITIVE_DISALLOW_KEYWORDS = (
    "admin", "login", "wp-admin", "wp-login", "private", "staging", "dev",
    "test", "backup", "tmp", "logs", "config", ".env", "secret", "internal",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching /robots.txt...")
    rb = await client.get("/robots.txt")
    robots_text = ""
    if rb is not None and rb.status_code == 200 and rb.text:
        robots_text = rb.text
        disallows = [m.group(1) for m in DISALLOW_RE.finditer(robots_text)]
        sensitive = [d for d in disallows if any(k in d.lower() for k in SENSITIVE_DISALLOW_KEYWORDS)]
        if sensitive:
            findings.append(
                Finding(
                    severity="low",
                    title=f"robots.txt advertises {len(sensitive)} sensitive-looking path(s)",
                    evidence="Disallow entries that look interesting:\n" + "\n".join(f"  - {d}" for d in sensitive[:20]),
                    remediation=(
                        "robots.txt is read by everyone, including attackers. Don't list staging or admin "
                        "URLs there — block them via auth or IP allow-listing instead. The Disallow only "
                        "asks polite bots to stay away; it doesn't restrict access."
                    ),
                    url=client.url("/robots.txt"),
                )
            )
        # Discover sitemap URLs
        sitemap_urls = [m.group(1) for m in SITEMAP_RE.finditer(robots_text)] or ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
        ctx.setdefault("shared", {})["sitemap_urls"] = sitemap_urls

    step("fetching /sitemap.xml...")
    sm_urls: list[str] = []
    for sm in (ctx.get("shared", {}).get("sitemap_urls") or ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]):
        path = sm if sm.startswith(("http://", "https://")) else sm
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        urls = URL_TAG_RE.findall(r.text)
        sm_urls.extend(urls)

    suspicious_paths = []
    for u in sm_urls:
        lower = u.lower()
        for k in ("wp-admin", "wp-login", "phpmyadmin", "adminer", "/admin/", ".env", "backup", "staging", "test."):
            if k in lower:
                suspicious_paths.append(u)
                break
    if suspicious_paths:
        findings.append(
            Finding(
                severity="medium",
                title=f"Sitemap exposes {len(suspicious_paths)} sensitive-looking URL(s)",
                evidence="\n".join(f"  - {u}" for u in suspicious_paths[:15]),
                remediation=(
                    "Filter the sitemap to exclude admin, staging, and test URLs. In WP: "
                    "`add_filter('wp_sitemaps_post_types', ...)` and similar filters; in Yoast/Rank Math, "
                    "use the exclusion settings."
                ),
                url=client.url("/sitemap.xml"),
            )
        )

    if sm_urls:
        findings.append(
            Finding(
                severity="info",
                title=f"Sitemap discovered {len(sm_urls)} URLs",
                evidence="First 5:\n" + "\n".join(f"  - {u}" for u in sm_urls[:5]),
                remediation="No action needed unless the sitemap is leaking pages you didn't intend to publish.",
                url=client.url("/sitemap.xml"),
            )
        )
    elif not findings:
        findings.append(
            Finding(
                severity="info",
                title="No robots.txt or sitemap.xml content to analyze",
                evidence="Neither /robots.txt nor common sitemap URLs returned usable content.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
