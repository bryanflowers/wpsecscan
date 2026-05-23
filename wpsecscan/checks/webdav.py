"""WebDAV / extended HTTP method enumeration.

Probes for `PROPFIND`, `MOVE`, `COPY`, `MKCOL` against the site root. These
methods indicate WebDAV is enabled. WebDAV on a public site is almost always
a misconfiguration — it allows file upload, move, and listing without auth
if the server is set up wrong.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

WEBDAV_METHODS = ("PROPFIND", "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    accepted: list[tuple[str, int]] = []
    step("probing HTTP OPTIONS to discover WebDAV methods...")
    r = await client.request("OPTIONS", "/")
    advertised = ""
    if r is not None:
        advertised = (r.headers.get("allow", "") or r.headers.get("Allow", "")).upper()
        dav = (r.headers.get("dav", "") or r.headers.get("DAV", "")).strip()
        if dav:
            findings.append(
                Finding(
                    severity="medium",
                    title=f"WebDAV advertised via DAV: {dav}",
                    evidence=f"OPTIONS / -> DAV: {dav}",
                    remediation=(
                        "Disable WebDAV at the web server. nginx: don't include the dav module; "
                        "Apache: `a2dismod dav dav_fs`. WebDAV on public WP rarely has a legitimate use."
                    ),
                    url=ctx["target"],
                )
            )

    # Try each method explicitly (some servers don't advertise but DO accept)
    for method in WEBDAV_METHODS:
        if advertised and method not in advertised:
            continue
        step(f"trying {method} /...")
        r = await client.request(method, "/")
        if r is None:
            continue
        # 200/207 = accepted; 405 = explicitly rejected
        if r.status_code in (200, 207, 102):
            accepted.append((method, r.status_code))

    if accepted:
        sev = "high" if any(m in ("MOVE", "COPY", "MKCOL", "LOCK") for m, _c in accepted) else "medium"
        findings.append(
            Finding(
                severity=sev,
                title=f"WebDAV methods accepted: {', '.join(m for m, _c in accepted)}",
                evidence="\n".join(f"  {m} / -> HTTP {c}" for m, c in accepted),
                remediation=(
                    "Block WebDAV methods at the web server. nginx: "
                    "`if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }`. "
                    "Apache: `<LimitExcept GET POST HEAD OPTIONS>Require all denied</LimitExcept>`."
                ),
                url=ctx["target"],
            )
        )
    elif not findings:
        findings.append(
            Finding(
                severity="info",
                title="WebDAV methods rejected",
                evidence=f"Probed {len(WEBDAV_METHODS)} WebDAV methods; none accepted.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
    return findings
