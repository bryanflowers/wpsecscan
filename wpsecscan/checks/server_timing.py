"""Server-Timing and debug-header leak check.

Modern frameworks add Server-Timing for browser dev-tool perf measurement.
On production it often leaks upstream architecture (cache hits, DB query
counts, framework names). Pair it with X-Request-ID / X-Trace-ID / X-Backend
etc. for a fingerprint surface.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

LEAKY_HEADERS = (
    "server-timing",
    "x-request-id",
    "x-trace-id",
    "x-backend-server",
    "x-served-by",
    "x-cache-hits",
    "x-debug-token",
    "x-debug-token-link",
    "x-runtime",
    "x-symfony-cache",
    "x-rails-cache",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-pingback",
    "x-mod-pagespeed",
    "x-litespeed-cache",
    "x-redirect-by",
    "x-php-version",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("inspecting / for Server-Timing and debug headers...")
    r = await client.get("/")
    if r is None:
        return findings

    leaked: dict[str, str] = {}
    for h in LEAKY_HEADERS:
        v = r.headers.get(h, "") or r.headers.get(h.title(), "")
        if v:
            leaked[h] = v

    if not leaked:
        findings.append(
            Finding(
                severity="info",
                title="No Server-Timing / debug-header leaks",
                evidence=f"None of the {len(LEAKY_HEADERS)} known leaky headers present on /.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Classify severity by leak content
    sensitive = []  # debug-mode indicators
    fingerprint = []  # version/server info
    for name, val in leaked.items():
        if "debug-token" in name or "runtime" in name or "aspnet-version" in name or "php-version" in name:
            sensitive.append((name, val))
        else:
            fingerprint.append((name, val))

    if sensitive:
        lines = "\n".join(f"  {n}: {v[:200]}" for n, v in sensitive)
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(sensitive)} debug-mode header(s) leaked",
                evidence=(
                    f"Headers that indicate debug/profiling mode is on in production:\n{lines}\n\n"
                    "X-Debug-Token-Link in particular often gives anonymous access to the Symfony profiler dashboard."
                ),
                remediation=(
                    "Disable debug mode / profiler in production config. Strip these headers at the edge if you need "
                    "them only for internal observability."
                ),
                url=ctx["target"],
            )
        )

    if fingerprint:
        lines = "\n".join(f"  {n}: {v[:200]}" for n, v in fingerprint)
        findings.append(
            Finding(
                severity="low",
                title=f"{len(fingerprint)} fingerprint header(s) present",
                evidence=(
                    f"Headers expose backend stack details:\n{lines}\n\n"
                    "These help attackers narrow CVE candidates and route traffic predictions."
                ),
                remediation=(
                    "Strip non-essential headers at the web server. Nginx: `more_clear_headers X-Powered-By "
                    "Server-Timing X-Trace-ID;` (requires headers-more module)."
                ),
                url=ctx["target"],
            )
        )

    return findings
