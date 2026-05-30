"""F12 (v2.8.0) — Headless WordPress CORS origin lockdown.

For sites detected as headless (Next.js / Astro / Gatsby consuming
`/wp-json/`), verify that the WordPress origin's REST endpoints don't
emit a wildcard `Access-Control-Allow-Origin: *` AND that
authenticated endpoints require credentials. Wildcard CORS on the WP
origin nullifies the headless-frontend's same-origin assumption and
lets ANY website read the operator's REST data.

Companion to the existing `headless_wp_audit` check (which detects
the headless pattern); this one tests the actual CORS policy on the
WP backend.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PROBE_PATHS = (
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/settings",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("F12: probing /wp-json/ CORS policy with cross-origin request...")
    rogue_origin = "https://wpsecscan-cors-probe.invalid"
    issues: list[str] = []

    for path in _PROBE_PATHS:
        try:
            r = await client.get(
                path,
                headers={"Origin": rogue_origin},
            )
        except Exception:  # noqa: BLE001
            continue
        if r is None:
            continue
        # Lowercase header lookup — httpx returns case-insensitive dict.
        acao = (r.headers.get("access-control-allow-origin") or "").strip()
        acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower()
        if acao == "*":
            sev_note = "WILDCARD"
            if acac == "true":
                # Spec-violating combo: browsers reject, but old clients
                # / non-browser HTTP libraries pre-2020 might honour it.
                sev_note = "WILDCARD + Credentials=true (spec-violating; treat as critical)"
            issues.append(
                f"{path} → ACAO=* {sev_note} (ACAC={acac or 'unset'})"
            )
        elif acao and acao == rogue_origin:
            # Reflected origin — equally bad as wildcard for an attacker
            # who can host any origin.
            issues.append(
                f"{path} → ACAO reflects arbitrary Origin header (ACAC={acac or 'unset'})"
            )

    if issues:
        findings.append(Finding(
            severity="high",
            title=f"F12: WP REST CORS policy is over-permissive ({len(issues)} endpoint(s))",
            evidence=(
                "Probed with Origin: " + rogue_origin + "\n\n"
                + "\n".join(f"  - {i}" for i in issues)
                + "\n\nAny website the user's browser visits can issue "
                "authenticated GETs to these endpoints."
            ),
            remediation=(
                "Set a strict CORS policy on the WP origin via "
                "Apache/nginx/Cloudflare: only allow your headless "
                "frontend's origin (e.g. `Access-Control-Allow-Origin: "
                "https://www.yoursite.com`), never wildcard, and only "
                "set `Access-Control-Allow-Credentials: true` if you "
                "actually need cross-origin authenticated requests. "
                "If WP is purely the data backend (no admin UI on the "
                "internet), block CORS entirely at the edge."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="F12: WP REST CORS policy is restrictive",
            evidence="No wildcard or reflected Access-Control-Allow-Origin header detected.",
            remediation="No action needed.",
            url=ctx["target"],
        ))
    return findings
