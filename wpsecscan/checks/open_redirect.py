"""Open-redirect probes on /wp-login.php?redirect_to= and common variants.

WP core's wp_safe_redirect() filters off-host destinations, but custom themes
and plugins sometimes ship their own redirect handlers that don't.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

ATTACKER_URL  = "https://wpsecscan-redirect-test.invalid/landed"
ATTACKER_HOST = "wpsecscan-redirect-test.invalid"

# (path, params_dict, description)
TARGETS = (
    ("/wp-login.php", {"redirect_to": ATTACKER_URL},     "wp-login.php?redirect_to=https://..."),
    ("/wp-login.php", {"redirect_to": "//" + ATTACKER_HOST}, "wp-login.php?redirect_to=//host (protocol-relative)"),
    ("/",             {"redirect_to": ATTACKER_URL},     "?redirect_to=https://..."),
    ("/",             {"redirect":    ATTACKER_URL},     "?redirect=https://..."),
    ("/",             {"return":      ATTACKER_URL},     "?return=https://..."),
    ("/",             {"url":         ATTACKER_URL},     "?url=https://..."),
    ("/",             {"next":        ATTACKER_URL},     "?next=https://..."),
)


def _location_offhost(loc: str, scan_host: str) -> bool:
    if not loc:
        return False
    if loc.startswith("//"):
        host = loc[2:].split("/", 1)[0]
        return bool(host) and host != scan_host
    p = urlparse(loc)
    if p.netloc and p.netloc != scan_host:
        return True
    return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    scan_host = urlparse(ctx["target"]).hostname or ""

    for path, params, desc in TARGETS:
        step(f"probing {desc}...")
        r = await client.get(path, params=params, follow_redirects=False)
        if r is None or r.status_code not in (301, 302, 303, 307, 308):
            continue
        loc = r.headers.get("location", "")
        if _location_offhost(loc, scan_host):
            target_host = urlparse(loc).netloc or loc[2:].split("/", 1)[0]
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Open redirect via {desc}",
                    evidence=(
                        f"GET {path} with {params} -> {r.status_code}\n"
                        f"  Location: {loc}\n"
                        f"  Target host '{target_host}' is not the scanned host '{scan_host}'."
                    ),
                    remediation=(
                        "Validate redirect targets against an allow-list, or use wp_safe_redirect() "
                        "which strips off-host destinations. Open redirects are commonly chained into "
                        "phishing campaigns and OAuth-token theft."
                    ),
                    url=client.url(path),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No open-redirect vectors found on common parameters",
                evidence=f"Probed {len(TARGETS)} common redirect parameter patterns.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
