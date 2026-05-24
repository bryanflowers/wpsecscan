"""{{TITLE}}

{{DESCRIPTION}}

Round-64 #152 — copy this file as a starting point for new checks.
The scaffolder at scripts/new-check.py fills the placeholders.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Example: probe a single path
    step("checking /example...")
    r = await client.get("/example")
    if r is None or r.status_code != 200:
        return findings

    body = r.text or ""
    if "expected-fingerprint" in body:
        findings.append(
            Finding(
                severity="medium",  # info | low | medium | high | critical
                title="Example finding title (short, action-oriented)",
                evidence=(
                    "Concrete proof: e.g. HTTP method + path + status\n"
                    "  + 1-2 lines of body snippet if relevant\n"
                    "  (don't include the user's secrets in evidence)"
                ),
                remediation=(
                    "Step-by-step fix instructions. Be concrete:\n"
                    "  - exact config lines, not 'fix the config'\n"
                    "  - exact commands, not 'run the right command'"
                ),
                url=client.url("/example"),
                extra={"key": "value"},  # optional structured payload
            )
        )

    return findings
