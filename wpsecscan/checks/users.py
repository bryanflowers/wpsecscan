from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

AUTHOR_REDIRECT_RE = re.compile(r"/author/([a-z0-9][a-z0-9_\-]*)/?", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    discovered: dict[int, str] = {}

    # 1. /?author=N (302 → /author/<slug>/)
    for author_id in range(1, 6):
        step(f"probing /?author={author_id}...")
        r = await client.get(f"/?author={author_id}")
        if r is None:
            continue
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("location", "")
            m = AUTHOR_REDIRECT_RE.search(loc)
            if m:
                discovered[author_id] = m.group(1)

    # Stash discovered usernames for downstream checks (HIBP, etc.)
    shared = ctx.setdefault("shared", {})
    shared.setdefault("users", set())

    if discovered:
        for slug in discovered.values():
            shared["users"].add(slug)
        lines = "\n".join(f"  - ID {i}: {s}" for i, s in discovered.items())
        findings.append(
            Finding(
                severity="medium",
                title=f"User enumeration via /?author=N possible ({len(discovered)} usernames disclosed)",
                evidence=f"GET /?author=N redirects revealed:\n{lines}",
                remediation=(
                    "Block author archive redirects: in functions.php, add a check that "
                    "redirects /?author=N to home when not logged in. Or use a security "
                    "plugin (Wordfence, iThemes Security) that has a 'disable user enumeration' setting."
                ),
                url=client.url("/?author=1"),
            )
        )

    # 2. /wp-json/wp/v2/users
    step("probing /wp-json/wp/v2/users...")
    rest = await client.get("/wp-json/wp/v2/users")
    if rest is not None and rest.status_code == 200:
        try:
            data = rest.json()
            if isinstance(data, list) and data:
                names = [u.get("slug") or u.get("name") for u in data
                         if isinstance(u, dict) and (u.get("slug") or u.get("name"))]
                # Require at least one real string slug/name. A plugin returning
                # [null] or [{}] at this path used to fire a false finding.
                if names:
                    for n in names:
                        shared["users"].add(n)
                    lines = "\n".join(f"  - {n}" for n in names)
                    findings.append(
                        Finding(
                            severity="medium",
                            title=f"REST /wp-json/wp/v2/users exposes {len(names)} user(s)",
                            evidence=f"Public REST endpoint returned:\n{lines}",
                            remediation=(
                                "Restrict the users REST endpoint. In functions.php:\n"
                                "  add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); unset($e['/wp/v2/users/(?P<id>[\\d]+)']); return $e; });\n"
                                "Or use a security plugin's REST hardening rule."
                            ),
                            url=client.url("/wp-json/wp/v2/users"),
                        )
                    )
        except ValueError:
            pass

    # 3. /?rest_route=/wp/v2/users (fallback)
    rest2 = await client.get("/?rest_route=/wp/v2/users")
    if rest2 is not None and rest2.status_code == 200:
        try:
            data = rest2.json()
            if isinstance(data, list) and data:
                # Same validity gate as the canonical path above
                valid_users = [u for u in data
                               if isinstance(u, dict) and (u.get("slug") or u.get("name"))]
                if valid_users:
                    findings.append(
                        Finding(
                            severity="medium",
                            title=f"REST users endpoint exposed via ?rest_route= query ({len(valid_users)} user(s))",
                            evidence=f"/?rest_route=/wp/v2/users returned {len(valid_users)} user(s).",
                            remediation="Same fix as /wp-json/wp/v2/users — filter out the users endpoint via rest_endpoints.",
                            url=client.url("/?rest_route=/wp/v2/users"),
                        )
                    )
        except ValueError:
            pass

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No user enumeration vectors detected",
                evidence="Tried /?author=1..5 (no redirects), /wp-json/wp/v2/users, /?rest_route= variant.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
