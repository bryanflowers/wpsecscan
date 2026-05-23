"""CORS misconfiguration check.

Send Origin: evil header on a few endpoints and check whether the server
reflects it into Access-Control-Allow-Origin, especially in combination
with Access-Control-Allow-Credentials: true.

The dangerous combo: ACAO reflects attacker origin + ACAC=true → any
malicious page can read authenticated responses from the WP site.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

PROBE_ORIGIN = "https://wpsecscan-cors-probe.invalid"
PATHS_TO_TEST = (
    "/",
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-admin/admin-ajax.php",
    "/wp-login.php",
)
# B8: full preflight matrix — common attacker origin shapes that should NOT be accepted
MATRIX_ORIGINS = (
    "null",                                              # iframe / data: URI sandbox origin
    "https://attacker.com",                              # plain attacker
    "https://wpsecscan-cors-probe.invalid",              # the default probe (kept for back-compat)
    "https://evil.example.com.attacker.com",             # subdomain-confusion lookalike
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    issues: list[dict] = []
    for path in PATHS_TO_TEST:
        step(f"CORS probe at {path}...")
        r = await client.get(path, headers={"Origin": PROBE_ORIGIN})
        if r is None:
            continue
        acao = r.headers.get("access-control-allow-origin", "") or r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("access-control-allow-credentials", "") or r.headers.get("Access-Control-Allow-Credentials", "")
        if not acao:
            continue

        sev = "info"
        title = ""
        if acao == "*" and acac.lower() == "true":
            # Browsers reject this combo, but some clients (curl, server-to-server) honor it.
            sev = "medium"
            title = f"CORS wildcard + credentials at {path}"
        elif acao == PROBE_ORIGIN:
            if acac.lower() == "true":
                sev = "high"
                title = f"CORS reflects attacker origin AND allows credentials at {path}"
            else:
                sev = "medium"
                title = f"CORS reflects attacker origin (no creds) at {path}"
        elif acao == "*":
            sev = "low"
            title = f"CORS wildcard at {path} (no credentials reflected)"
        else:
            # Allow-listed origin — boring
            continue

        issues.append({
            "path": path,
            "severity": sev,
            "title": title,
            "acao": acao,
            "acac": acac,
        })

    for issue in issues:
        findings.append(
            Finding(
                severity=issue["severity"],
                title=issue["title"],
                evidence=(
                    f"GET {issue['path']} with Origin: {PROBE_ORIGIN}\n"
                    f"  Access-Control-Allow-Origin: {issue['acao']}\n"
                    f"  Access-Control-Allow-Credentials: {issue['acac'] or '(not set)'}\n\n"
                    "Attacker-origin reflection + credentials = any malicious page can read authenticated responses. "
                    "Wildcard + credentials is rejected by browsers but honored by some non-browser clients."
                ),
                remediation=(
                    "Use an explicit allow-list of trusted origins, never reflect the Origin header. "
                    "For plugin-controlled CORS, audit the rest_pre_serve_request filter and any CORS-handling plugin. "
                    "Server-level (Nginx): explicit static `add_header Access-Control-Allow-Origin https://trusted-origin.com always;`."
                ),
                url=client.url(issue["path"]),
            )
        )

    # B8: full preflight matrix — try each attacker-origin shape against the API
    # in an OPTIONS preflight. Any reflection of `null` or subdomain-confusion
    # is a higher severity than the single fixed probe above.
    matrix_hits: list[tuple[str, str, str]] = []  # (origin, path, acao)
    for origin in MATRIX_ORIGINS:
        for path in ("/wp-json/", "/wp-json/wp/v2/posts"):
            step(f"CORS preflight: Origin={origin} -> {path}...")
            r = await client.request(
                "OPTIONS", path,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-Wpsec-Test",
                },
            )
            if r is None:
                continue
            acao = (r.headers.get("access-control-allow-origin", "")
                    or r.headers.get("Access-Control-Allow-Origin", ""))
            if acao and (acao == origin or acao == "*"):
                matrix_hits.append((origin, path, acao))

    for origin, path, acao in matrix_hits:
        # `null` reflection is particularly dangerous — sandboxed iframes load with Origin: null
        sev = "high" if origin == "null" else "medium"
        title_prefix = "CORS reflects null origin" if origin == "null" else "CORS preflight reflects attacker origin"
        findings.append(
            Finding(
                severity=sev,
                title=f"{title_prefix} at {path}",
                evidence=(
                    f"OPTIONS {path} with Origin: {origin}\n"
                    f"  Access-Control-Allow-Origin: {acao}\n\n"
                    f"{'A sandboxed iframe / data: URI has Origin: null — reflecting it lets any malicious page read responses.' if origin == 'null' else 'The preflight accepted an arbitrary attacker-controlled origin.'}"
                ),
                remediation=(
                    "Use an EXPLICIT allow-list. Reject `null` entirely. Never reflect the request "
                    "Origin without validating against a static list."
                ),
                url=client.url(path),
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No CORS reflection observed",
                evidence=f"Probed {len(PATHS_TO_TEST)} endpoints (simple GET) + {len(MATRIX_ORIGINS)}×2 preflight matrix; none reflected attacker origins.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
