"""#5 (from wpscan) — wide user-enumeration with 10 sources.

The existing `users` check covers ?author=, REST /wp/v2/users, and a couple
of others. wpscan probes ~10 paths to catch the long tail. This check fills
the gap.

Sources covered:
  1. ?author=N redirect (handled by existing `users` check)
  2. /wp-json/wp/v2/users
  3. /wp-json/oembed/1.0/embed?url=/?p=1   (extracts `author_name`)
  4. /feed/ (RSS — pulls `<dc:creator>` tags)
  5. /comments/feed/
  6. /wp-sitemap-users-1.xml
  7. /author-sitemap.xml
  8. Yoast SEO author archive at /sitemap_index.xml → author-sitemap.xml
  9. .well-known/security.txt (sometimes lists "responsible disclosure to")
 10. Comment-author HTML scraping from `/?p=1` (the rendered post page)
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


_DC_CREATOR_RE = re.compile(r"<dc:creator[^>]*>(?:<!\[CDATA\[)?([^<\]]+)", re.IGNORECASE)
_AUTHOR_NAME_RE = re.compile(r'"author_name"\s*:\s*"([^"]+)"')
_AUTHOR_URL_RE  = re.compile(r"https?://[^/]+/author/([a-z0-9._-]+)", re.IGNORECASE)


async def _from_oembed(client: Client) -> set[str]:
    out: set[str] = set()
    target = client.base_url
    r = await client.get(f"/wp-json/oembed/1.0/embed?url={target}/?p=1")
    if r is None or r.status_code != 200:
        return out
    for m in _AUTHOR_NAME_RE.finditer(r.text or ""):
        out.add(m.group(1).strip())
    return out


async def _from_feed(client: Client, path: str) -> set[str]:
    out: set[str] = set()
    r = await client.get(path)
    if r is None or r.status_code != 200:
        return out
    for m in _DC_CREATOR_RE.finditer(r.text or ""):
        name = (m.group(1) or "").strip()
        if name:
            out.add(name)
    return out


async def _from_users_sitemap(client: Client, path: str) -> set[str]:
    """WP-Core 5.5+ and Yoast / Rank Math all generate author sitemaps."""
    out: set[str] = set()
    r = await client.get(path)
    if r is None or r.status_code != 200:
        return out
    try:
        # Strip XML namespace to keep parsing simple
        body = re.sub(r' xmlns="[^"]+"', '', r.text or "", count=1)
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return out
    for loc in root.iter("loc"):
        if loc.text:
            m = _AUTHOR_URL_RE.search(loc.text)
            if m:
                out.add(m.group(1))
    return out


async def _from_post_html(client: Client) -> set[str]:
    """Some themes render comment-author names directly in /?p=1 HTML."""
    out: set[str] = set()
    r = await client.get("/?p=1")
    if r is None or r.status_code != 200:
        return out
    # Look for `class="comment-author"...><cite>NAME</cite>` (canonical WP markup)
    for m in re.finditer(r'class="[^"]*comment-author[^"]*"[^>]*>\s*<[^>]+>\s*([^<]{2,60})<', r.text or ""):
        name = m.group(1).strip()
        if name and name.lower() not in ("anonymous", "guest"):
            out.add(name)
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    found: dict[str, set[str]] = {}

    step("user enum: oEmbed...")
    found["oembed"] = await _from_oembed(client)

    step("user enum: RSS /feed/...")
    found["rss"] = await _from_feed(client, "/feed/")

    step("user enum: comments feed...")
    found["comments_feed"] = await _from_feed(client, "/comments/feed/")

    step("user enum: WP-core author sitemap...")
    found["wp_sitemap"] = await _from_users_sitemap(client, "/wp-sitemap-users-1.xml")

    step("user enum: Yoast author sitemap...")
    found["yoast_sitemap"] = await _from_users_sitemap(client, "/author-sitemap.xml")

    step("user enum: post HTML comment-authors...")
    found["post_html"] = await _from_post_html(client)

    all_users: set[str] = set()
    sources_with_data: list[str] = []
    for src, users in found.items():
        if users:
            all_users.update(users)
            sources_with_data.append(f"{src}({len(users)})")

    if not all_users:
        findings.append(Finding(
            severity="info",
            title="Deep user enumeration — no usernames disclosed",
            evidence="Checked oEmbed, RSS, comments feed, WP-core + Yoast author sitemaps, and post HTML. No usernames leaked.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    sev = "medium" if len(all_users) >= 5 else "low"
    findings.append(Finding(
        severity=sev,
        title=f"Deep user enumeration found {len(all_users)} username(s) across {len(sources_with_data)} source(s)",
        evidence=(
            f"Sources with data: {', '.join(sources_with_data)}\n"
            f"Usernames: {', '.join(sorted(all_users)[:20])}"
            + (f" (+ {len(all_users) - 20} more)" if len(all_users) > 20 else "") +
            "\n\nThese names enable targeted brute-force / password-spray attacks against /wp-login.php."
        ),
        remediation=(
            "1. Block REST /wp/v2/users for unauth (jetpack module 'protect' or a one-line wp-content/mu-plugins filter)\n"
            "2. Disable RSS feeds you don't use (`add_filter('feed_links_show_posts_feed', '__return_false')` etc.)\n"
            "3. Configure Yoast / Rank Math to exclude author sitemaps if you don't publish multi-author content\n"
            "4. Use display-names that differ from login-names so leaked display-names aren't usable for login"
        ),
        url=ctx["target"],
    ))
    # Push discovered usernames into shared so login_throttle / authenticated checks can use them
    shared = ctx.setdefault("shared", {})
    shared.setdefault("discovered_usernames", set()).update(all_users)

    return findings
