"""Deep probe for exposed Adminer / phpMyAdmin login pages.

The existing exposed_files check flags `/adminer.php` and `/phpmyadmin/`
on 200/403 status. This check goes deeper: when a 200 response is
returned, parse the body for the actual Adminer/phpMyAdmin login form,
which means the tool is fully reachable from the public internet (not
just behind a static-file rewrite).
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


_PROBES = (
    ("/adminer.php",          ('id="loginform"', '"adminer"', 'Adminer.input'), "Adminer"),
    ("/adminer/index.php",    ('id="loginform"', '"adminer"',),                 "Adminer"),
    ("/phpmyadmin/index.php", ('phpMyAdmin', 'pma_username'),                   "phpMyAdmin"),
    ("/pma/index.php",        ('phpMyAdmin', 'pma_username'),                   "phpMyAdmin"),
    ("/dbadmin/index.php",    ('phpMyAdmin', 'pma_username'),                   "phpMyAdmin (dbadmin alias)"),
    ("/myadmin/",             ('phpMyAdmin', 'pma_username'),                   "phpMyAdmin (myadmin alias)"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    for path, markers, tool in _PROBES:
        step(f"probing {path} for {tool} login form...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        body = r.text[:50000]  # cap to avoid scanning huge responses
        if any(m in body for m in markers):
            findings.append(Finding(
                severity="high",
                title=f"Public {tool} login form reachable at {path}",
                evidence=(
                    f"GET {path} → HTTP 200 with {tool} login form in the response body. "
                    "This is a fully-functional database-administration tool reachable "
                    "from the public internet. An attacker only needs valid DB "
                    "credentials (or a credential-stuffing match) to log in."
                ),
                remediation=(
                    f"1. Delete {tool} from the web root immediately if it's not in "
                    "active use. It's not part of WordPress; it was probably installed "
                    "ad-hoc during a migration or troubleshooting session.\n"
                    f"2. If you need {tool}, restrict access to specific IPs at the "
                    "web server (nginx `allow X; deny all;`) or move it behind HTTP "
                    "basic auth.\n"
                    f"3. Verify the DB user {tool} connects as is limited to the WP "
                    "database — not a global root account."
                ),
                url=client.url(path),
            ))
    return findings
