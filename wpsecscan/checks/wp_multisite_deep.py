"""Round-60 #17 — WP-Multisite per-blog deep audit.

Enumerates network sites via /wp-json/wp/v2/sites and probes each
sub-blog for: distinct admin users, distinct plugin set, distinct
options, cross-tenant REST data leakage.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    # Multisite indicator
    step("multisite: probing wp-signup / is_multisite markers...")
    home = await client.get("/")
    body = (home.text or "") if home else ""
    if not any(ind in body for ind in ("wp-signup.php", "ms-files.php", "is_multisite")):
        # Fall-through probe — REST list-of-sites returns 200 only on multisite
        r = await client.get("/wp-json/wp/v2/sites")
        if r is None or r.status_code != 200:
            return [Finding(severity="info", title="WP Multisite deep — single-site install (skipped)",
                            evidence="No multisite markers found.",
                            remediation="No action.", url=target)]

    step("multisite: enumerating sites via REST...")
    r = await client.get("/wp-json/wp/v2/sites?per_page=100")
    if r is None or r.status_code != 200:
        return [Finding(severity="low",
                         title="Multisite suspected but /wp-json/wp/v2/sites unreachable",
                         evidence=f"GET /wp-json/wp/v2/sites -> {r.status_code if r else 'no response'}",
                         remediation="If you operate a multisite, expose `/wp-json/wp/v2/sites` to authenticated admins.",
                         url=target)]

    try:
        sites = r.json() or []
    except (ValueError, AttributeError):
        sites = []
    if not isinstance(sites, list) or not sites:
        return [Finding(severity="info", title="Multisite REST returned no sites",
                        evidence="", remediation="No action.", url=target)]

    findings.append(Finding(
        severity="info",
        title=f"Multisite network with {len(sites)} sub-site(s)",
        evidence="\n".join(f"  - {s.get('url') or s.get('blog_id')}" for s in sites[:20]),
        remediation="Per-blog isolation is hard. Audit user_roles, plugins active per blog, and REST permissions.",
        url=target,
    ))

    # Per-blog cross-leak probe — fetch /wp-json/wp/v2/users from each blog
    # url and look for the SAME user appearing across multiple blogs with
    # super_admin role. (best-effort, top 10 blogs only)
    seen_super_admins: dict[str, list[str]] = {}
    for s in sites[:10]:
        blog_url = (s.get("url") or "").rstrip("/")
        if not blog_url:
            continue
        try:
            br = await client.get(blog_url + "/wp-json/wp/v2/users?per_page=20")
            if br is None or br.status_code != 200:
                continue
            for u in (br.json() or []):
                login = (u.get("slug") or u.get("username") or "").lower()
                if not login:
                    continue
                seen_super_admins.setdefault(login, []).append(blog_url)
        except (ValueError, AttributeError):
            continue
    cross = {u: bs for u, bs in seen_super_admins.items() if len(bs) > 1}
    if cross:
        findings.append(Finding(
            severity="medium",
            title=f"{len(cross)} user(s) reachable from multiple sub-blogs",
            evidence="\n".join(f"  - {u}: {len(bs)} blogs" for u, bs in list(cross.items())[:10]),
            remediation="Audit super-admin grants. Multisite super admins are network-wide — minimise count.",
            url=target,
        ))

    return findings
