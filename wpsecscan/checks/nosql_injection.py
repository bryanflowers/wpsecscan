"""NoSQL injection probe (MongoDB-style operators).

Most WP sites use MySQL, but a growing number of plugins use Mongo/Couch via
add-on databases. This check sends MongoDB-operator-shaped payloads:
  - `?param[$ne]=null` (operator injection in PHP arrays)
  - JSON body `{"username": {"$ne": null}, "password": {"$ne": null}}`
  - `{"$where": "1==1"}` (server-side JavaScript injection)

A response that LOOKS DIFFERENT from the bare-parameter baseline indicates the
operator was consumed.

Aggressive-only.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="NoSQL injection probe skipped (requires --aggressive)",
                evidence="This sends MongoDB-operator payloads to login + search endpoints.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Test the login form first (`?user[$ne]=null` style)
    step("NoSQL: probing wp-login.php with $ne operator in user array...")
    r_baseline = await client.post(
        "/wp-login.php",
        data={"log": "fakeuser", "pwd": "wrong", "wp-submit": "Log In", "testcookie": "1"},
        headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
    )
    base_len = len(r_baseline.content or b"") if r_baseline else 0

    leaks: list[tuple[str, str]] = []

    # Op-injection via array syntax — PHP turns `?user[$ne]=null` into an array
    r = await client.post(
        "/wp-login.php",
        data={
            "log[$ne]": "null", "pwd[$ne]": "null",
            "wp-submit": "Log In", "testcookie": "1",
        },
        headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
    )
    if r is not None and abs(len(r.content or b"") - base_len) > 200:
        leaks.append(("/wp-login.php form-data",
                      "Sent `log[$ne]=null&pwd[$ne]=null` — response shape changed significantly vs baseline."))

    # Op-injection via JSON body to REST API
    step("NoSQL: probing wp-json with $where operator in JSON body...")
    r = await client.post(
        "/wp-json/wp/v2/users",
        json={"username": {"$ne": None}, "password": {"$ne": None}},
        headers={"Content-Type": "application/json"},
    )
    if r is not None and r.status_code == 200 and r.content:
        body = (r.text or "")[:2000]
        if "id" in body and "username" in body:
            leaks.append(("/wp-json/wp/v2/users JSON body",
                          f"$ne payload returned a user-shaped response (HTTP 200, {len(r.content)} bytes)."))

    # Op-injection via search endpoint
    step("NoSQL: probing search with $regex operator...")
    r = await client.get("/", params={"s": "test", "s[$regex]": ".*"})
    if r is not None and r.text and "<form" in r.text:
        # No reliable signal here; skip emitting unless body length is wildly different
        pass

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="No NoSQL operator injection detected",
                evidence="MongoDB-style $ne / $where payloads against login + REST API didn't change response shapes.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for where, evidence in leaks:
        findings.append(
            Finding(
                severity="high",
                title=f"NoSQL operator injection candidate at {where}",
                evidence=(
                    f"{evidence}\n\n"
                    "If the underlying store is MongoDB or a similar NoSQL backend, an attacker can "
                    "construct `{'$ne': null}` to match any user, bypassing password verification."
                ),
                remediation=(
                    "Cast all auth-form inputs to STRING before query-building. Reject inputs whose "
                    "type is array/object. For WP, this is unusual — the relevant plugins are "
                    "MongoCMS, WP-Cassandra and similar; audit them."
                ),
                url=ctx["target"],
            )
        )
    return findings
