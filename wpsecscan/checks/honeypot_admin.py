"""Round-60 #19 — honeypot mode (passive intelligence-gathering check).

Detects if the target site already deploys a fake-admin honeypot (e.g.
the `wp-honeypot` plugin, or a manually-placed `/wp-admin-login.php`
that logs attackers). Doesn't deploy one — that's the user's choice and
requires write access.

If the user wants WPSecScan itself to deploy a honeypot, they install
the companion plugin which exposes a 1-click "Enable login honeypot"
admin action (see wp-plugin/wpsecscan-companion).
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


HONEYPOT_PATHS = (
    "/wp-honeypot.php",
    "/wp-admin-login.php",
    "/admin-fake.php",
    "/honeypot/",
)
PLUGIN_PATHS = (
    "/wp-content/plugins/honeypot-toolkit/honeypot.php",
    "/wp-content/plugins/wp-spamshield/wp-spamshield.php",
    "/wp-content/plugins/cleantalk-spam-protect/cleantalk.php",
    "/wp-content/plugins/antispam-bee/antispam_bee.php",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    detected: list[str] = []
    for path in HONEYPOT_PATHS:
        step(f"honeypot probe {path}...")
        r = await client.head(path)
        if r is not None and r.status_code == 200:
            detected.append(path)

    plugin_hits: list[str] = []
    for path in PLUGIN_PATHS:
        r = await client.get(path)
        if r is not None and r.status_code == 200 and r.text:
            plugin_hits.append(path)

    if detected or plugin_hits:
        findings.append(Finding(
            severity="info",
            title=f"Honeypot / anti-spam detected ({len(detected) + len(plugin_hits)})",
            evidence="Paths: " + ", ".join(detected + plugin_hits),
            remediation="Confirm the honeypot logs attacker IPs. Tail those logs into fail2ban / Cloudflare WAF block list.",
            url=target,
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="No honeypot / anti-spam detected",
            evidence="None of the common honeypot/anti-spam paths or plugins detected.",
            remediation=("Consider deploying a login honeypot (a fake /wp-admin-login.php that "
                          "logs the attacker IP). Plugins: 'WP Honeypot' (community) or install the "
                          "WPSecScan companion plugin and tick 'Enable login honeypot'."),
            url=target,
        ))
    return findings
