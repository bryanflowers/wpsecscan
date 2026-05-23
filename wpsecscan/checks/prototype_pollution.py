"""Prototype-pollution probe (client + server-side via JSON middleware).

Sends `?__proto__[polluted]=wpsec` and `?constructor[prototype][polluted]=wpsec`
style payloads. If the value is reflected in a response or appears in a
Set-Cookie / response header / inline JSON config, the server's JSON parsing
or merge utility is vulnerable.

Aggressive-only (sends crafted URL parameters).
"""
from __future__ import annotations

import secrets

from ..http import Client
from ..models import Finding

PAYLOADS = (
    ("__proto__[wpsec_pp]",           "value-A"),
    ("constructor[prototype][wpsec_pp]", "value-B"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="Prototype-pollution probe skipped (requires --aggressive)",
                evidence="This check sends crafted query parameters; opt in via --aggressive.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    canary = "wpsec-pp-" + secrets.token_hex(4)
    paths_to_probe = ["/", "/wp-json/", "/?p=1", "/wp-admin/admin-ajax.php?action=heartbeat"]

    leaks: list[tuple[str, str, str]] = []  # (path, payload, evidence-snippet)
    for path in paths_to_probe:
        for key, _v in PAYLOADS:
            step(f"probing {path} with {key[:30]}...")
            r = await client.get(path, params={key: canary})
            if r is None:
                continue
            body = (r.text or "")[:80000]
            hdrs = " ".join(f"{k}: {v}" for k, v in (r.headers or {}).items())
            # Reflection is the indicator
            if canary in body:
                leaks.append((path, key, "reflected in response body"))
            elif canary in hdrs:
                leaks.append((path, key, "reflected in response headers"))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="No prototype-pollution reflections detected",
                evidence=(
                    f"Probed {len(paths_to_probe)} paths with {len(PAYLOADS)} payload shape(s); "
                    f"none reflected the canary `{canary}`."
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for path, key, ev in leaks:
        findings.append(
            Finding(
                severity="medium",
                title=f"Prototype-pollution candidate at {path} via `{key}`",
                evidence=(
                    f"Sent `?{key}={canary}` to {path}; canary {ev}.\n"
                    "If this value reaches a JavaScript merge utility (jQuery.extend, lodash.merge, "
                    "Object.assign with untrusted input) it can corrupt Object.prototype globally."
                ),
                remediation=(
                    "Reject parameter names containing `__proto__`, `prototype`, or `constructor` at "
                    "the entry point (e.g. plugin REST controller). For client-side: update jQuery to "
                    ">=3.4.0 and lodash to >=4.17.12 (both have prototype-pollution fixes)."
                ),
                url=client.url(path),
            )
        )
    return findings
