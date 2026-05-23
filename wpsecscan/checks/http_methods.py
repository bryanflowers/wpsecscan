"""HTTP method enumeration — checks OPTIONS, TRACE, PUT, DELETE, PATCH."""
from __future__ import annotations

from ..http import Client
from ..models import Finding

DANGEROUS_METHODS = ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PROPFIND", "MKCOL")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # OPTIONS — the server should advertise what methods it accepts
    step("sending OPTIONS /...")
    opt = await client.request("OPTIONS", "/")
    allow = ""
    if opt is not None:
        allow = opt.headers.get("allow", "") or opt.headers.get("Allow", "")
        if allow:
            findings.append(
                Finding(
                    severity="info",
                    title=f"OPTIONS / advertises methods: {allow}",
                    evidence=f"Allow: {allow}",
                    remediation="No action unless dangerous methods are listed (see below).",
                    url=ctx["target"],
                )
            )

    # Probe each dangerous method directly — server might accept methods not in Allow
    dangerous_seen: list[tuple[str, int]] = []
    for m in DANGEROUS_METHODS:
        step(f"probing {m} /...")
        r = await client.request(m, "/")
        if r is None:
            continue
        # 200/201/204 = method actually worked, bad. 405/501 = correctly rejected.
        # 401/403 = auth-gated, mildly interesting.
        if r.status_code in (200, 201, 202, 204, 207, 300, 301, 302):
            dangerous_seen.append((m, r.status_code))

    if dangerous_seen:
        lines = "\n".join(f"  - {m} -> HTTP {sc}" for m, sc in dangerous_seen)
        sev = "high" if any(m in ("PUT", "DELETE", "PROPFIND", "MKCOL") for m, _ in dangerous_seen) else "medium"
        findings.append(
            Finding(
                severity=sev,
                title=f"{len(dangerous_seen)} dangerous HTTP method(s) appear accepted",
                evidence=lines + "\nMethods returning 2xx/3xx implies the server is handling them rather than rejecting with 405.",
                remediation=(
                    "Disable unsafe methods at the server level. Nginx: `if ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$) { return 405; }`. "
                    "Apache: `<LimitExcept GET POST HEAD OPTIONS>Require all denied</LimitExcept>`. "
                    "TRACE in particular enables Cross-Site Tracing if you have any reflective vulns elsewhere."
                ),
                url=ctx["target"],
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No dangerous HTTP methods accepted",
                evidence=f"Probed {len(DANGEROUS_METHODS)} methods; all rejected.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
