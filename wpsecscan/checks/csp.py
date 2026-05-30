"""Deep CSP analysis.

The tls_headers check flags a missing CSP. This one *grades* a present CSP —
scoring usage of unsafe-inline, unsafe-eval, wildcard sources, and missing
directives that meaningfully harden the page.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

CRITICAL_DIRECTIVES = (
    "default-src",
    "script-src",
    "object-src",
    "frame-ancestors",
    "base-uri",
)

UNSAFE_TOKENS = ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "data:", "blob:", "http:")


def _parse_csp(raw: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        if not bits:
            continue
        name = bits[0].lower()
        out[name] = bits[1:]
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching / to grade CSP...")
    r = await client.get("/")
    if r is None:
        return findings
    csp_raw = r.headers.get("content-security-policy", "")
    if not csp_raw:
        # Already flagged by tls_headers; just emit an info here so the check has output.
        findings.append(
            Finding(
                severity="info",
                title="No Content-Security-Policy header present (deep grading skipped)",
                evidence="See the 'TLS & security headers' check for the basic header-presence finding.",
                remediation="Adding a baseline CSP — even `default-src 'self' https:; object-src 'none'; frame-ancestors 'self'` — blocks the most common XSS payloads.",
                url=ctx["target"],
            )
        )
        return findings

    parsed = _parse_csp(csp_raw)
    issues: list[tuple[str, str]] = []

    # 1. Missing critical directives
    for d in CRITICAL_DIRECTIVES:
        if d not in parsed:
            issues.append(("medium", f"Missing directive: {d}"))

    # 2. Unsafe tokens in script-src or default-src
    for d in ("default-src", "script-src", "script-src-elem"):
        if d in parsed:
            for tok in parsed[d]:
                if tok.lower() in UNSAFE_TOKENS:
                    sev = "high" if "unsafe-inline" in tok.lower() or "unsafe-eval" in tok.lower() else "medium"
                    issues.append((sev, f"{d} allows {tok}"))

    # 3. object-src not 'none'
    if "object-src" in parsed:
        vals = [v.lower() for v in parsed["object-src"]]
        if "'none'" not in vals:
            issues.append(("medium", f"object-src is not 'none' (got: {' '.join(parsed['object-src'])})"))

    # 4. frame-ancestors absent or wildcard
    if "frame-ancestors" in parsed:
        vals = [v.lower() for v in parsed["frame-ancestors"]]
        if "*" in vals:
            issues.append(("medium", "frame-ancestors allows * (clickjacking risk)"))

    # 5. base-uri absent (enables base-tag injection)
    if "base-uri" not in parsed:
        issues.append(("low", "base-uri not set — base-tag injection mitigation is missing"))

    # F17 (v2.8.0) — Trusted Types CSP directive detection. Chrome 124+
    # (April 2024) enforces `require-trusted-types-for 'script'` as the
    # OWASP-2025-A03 baseline mitigation against DOM-XSS sink abuse.
    # Edge + Brave shipped it; Firefox + Safari still behind a flag.
    # Absence is defence-in-depth gap, not a vulnerability — flagged
    # low. A WP site that emits a CSP at all but lacks Trusted Types
    # is leaving an obvious modern hardening on the table.
    has_require_tt = "require-trusted-types-for" in parsed
    has_tt_policy = "trusted-types" in parsed
    if not has_require_tt:
        issues.append((
            "low",
            "Missing `require-trusted-types-for 'script'` directive — "
            "DOM-XSS sink mitigation not enforced in Chromium browsers",
        ))
    elif not has_tt_policy:
        # require-trusted-types-for present but no policy whitelist —
        # this enforces nothing useful since any policy can be created.
        issues.append((
            "low",
            "`require-trusted-types-for` set but `trusted-types` policy "
            "whitelist is missing — any policy name can be created, "
            "defeating the protection",
        ))

    if not issues:
        findings.append(
            Finding(
                severity="info",
                title="CSP is reasonably hardened",
                evidence=f"Policy: {csp_raw[:300]}{'...' if len(csp_raw) > 300 else ''}",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    else:
        worst_sev = "low"
        for sev, _ in issues:
            if sev == "high":
                worst_sev = "high"
                break
            if sev == "medium" and worst_sev != "high":
                worst_sev = "medium"
        findings.append(
            Finding(
                severity=worst_sev,
                title=f"CSP has {len(issues)} weakness(es)",
                evidence=(
                    f"Policy: {csp_raw[:300]}{'...' if len(csp_raw) > 300 else ''}\n\nIssues:\n"
                    + "\n".join(f"  - [{s}] {msg}" for s, msg in issues)
                ),
                remediation=(
                    "Tighten the CSP: remove 'unsafe-inline' / 'unsafe-eval' (use nonces or hashes); set "
                    "`object-src 'none'`, `frame-ancestors 'self'`, `base-uri 'self'`. Start in report-only "
                    "mode (`Content-Security-Policy-Report-Only`) to measure breakage before enforcing."
                ),
                url=ctx["target"],
            )
        )

    return findings
