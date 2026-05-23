"""WP Engine-specific misconfiguration probes.

WP Engine (the host) blocks dozens of common paths via their `wpe_common_blocked_paths`
rule — but their own private paths (/wpe_common.php, /_wpeprivate/, /wp-config.txt) are
occasionally reachable on misconfigured sites.

Only runs against sites that fingerprint as WP Engine (X-Powered-By: WP Engine
or Server: nginx-wpengine).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

WPENGINE_PATHS = (
    "/_wpeprivate/",
    "/_wpeprivate/config.json",
    "/wpe_common.php",
    "/wp-config.txt",            # WP Engine sample-config name
    "/wp-content/mu-plugins/wpengine-common/plugin.php",
    "/wp-content/mu-plugins/wpe-cli.php",
    "/cgi-bin/test-cgi",         # historical leak
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fingerprinting host as WP Engine...")
    r = await client.get("/")
    is_wpe = False
    if r is not None:
        hdrs = {k.lower(): (v or "") for k, v in (r.headers or {}).items()}
        if "wpe" in hdrs.get("server", "").lower() or "wp engine" in hdrs.get("x-powered-by", "").lower():
            is_wpe = True
        if "wpe" in (r.text or "")[:4000].lower() or "wpengine" in (r.text or "")[:4000].lower():
            is_wpe = True

    if not is_wpe:
        findings.append(
            Finding(
                severity="info",
                title="Host is not WP Engine — WP Engine-specific probes skipped",
                evidence="No WP Engine fingerprint in server headers or homepage HTML.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    leaks: list[tuple[str, int]] = []
    for p in WPENGINE_PATHS:
        step(f"probing WP Engine path {p}...")
        r = await client.get(p)
        if r is None:
            continue
        # 200 / 403 with body content both indicate the path exists.
        if r.status_code == 200 or (r.status_code == 403 and r.content and len(r.content) > 100):
            leaks.append((p, r.status_code))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="WP Engine host detected, no private-path leaks",
                evidence=f"Probed {len(WPENGINE_PATHS)} WP Engine private paths; all returned 404.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for p, code in leaks:
        sev = "high" if "config" in p or "_wpeprivate" in p else "medium"
        findings.append(
            Finding(
                severity=sev,
                title=f"WP Engine private path reachable: {p} (HTTP {code})",
                evidence=(
                    f"GET {p} -> {code}. WP Engine's `wpe_common_blocked_paths` "
                    "should return 404 for this. A reachable response suggests a rule "
                    "misconfiguration or the site has been moved off WP Engine without "
                    "fully migrating away from their private code."
                ),
                remediation=(
                    "If the site is still on WP Engine: open a support ticket — their CDN rule "
                    "isn't filtering this path. If the site has migrated, remove the WP Engine "
                    "mu-plugins from /wp-content/mu-plugins/ and rebuild caches."
                ),
                url=client.url(p),
            )
        )
    return findings
