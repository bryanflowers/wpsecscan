"""Probe known-vulnerable file-upload endpoints for unauthenticated reachability.

We do NOT actually upload payloads. We just check whether the endpoints
respond as if they would accept an upload (typical signals: 200 with a
specific JSON shape, 400 'no file' error, etc.) — which means an authn
gate is missing.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (path, method, expected-reachable-hint-codes, description, severity-if-confirmed)
TARGETS = (
    ("/wp-admin/async-upload.php",                        "POST", [200, 400, 500],          "core async-upload (should require auth)", "high"),
    ("/wp-admin/admin-ajax.php",                          "POST", [200],                    "admin-ajax with upload-attachment action", "medium"),
    ("/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "POST", [200, 400, 500], "wp-file-manager elFinder connector", "critical"),
    ("/wp-content/plugins/contact-form-7/includes/captcha/", "GET", [200],                  "contact-form-7 captcha dir (CVE history)", "low"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path, method, ok_codes, desc, sev in TARGETS:
        step(f"probing {desc}...")
        if method == "POST":
            r = await client.post(path, content="", headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            r = await client.get(path)
        if r is None:
            continue
        if r.status_code in ok_codes:
            body_snippet = (r.text or "")[:200].replace("\n", " ")
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Upload endpoint reachable unauthenticated: {desc}",
                    evidence=(
                        f"{method} {path} -> HTTP {r.status_code}\n"
                        f"  body: {body_snippet}\n"
                        "This doesn't confirm an upload succeeded — only that the endpoint responds to anonymous requests. "
                        "Real exploitation depends on parameter handling inside the endpoint."
                    ),
                    remediation=(
                        "Block this URL via .htaccess / nginx unless required, and require authentication for any "
                        "endpoint that handles uploads. For wp-file-manager specifically, the legacy elFinder "
                        "connector should be removed entirely."
                    ),
                    url=client.url(path),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No known upload endpoints reachable unauthenticated",
                evidence=f"Probed {len(TARGETS)} known upload endpoints.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
