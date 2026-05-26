"""WordPress Heartbeat API frontend detection.

The Heartbeat API (`/wp-admin/admin-ajax.php?action=heartbeat`) polls every
15 seconds by default. It's needed in `/wp-admin` (post autosave, lock
detection) but rarely on the front-end of the public site, where it just
adds a persistent AJAX load on every visitor. This check looks for
`wp-heartbeat` references in the public homepage HTML and flags it as
low-severity perf/load advice with a one-line `wp_deregister_script` fix.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_HEARTBEAT_SCRIPT_RE = re.compile(r"wp-heartbeat|wp/v1/heartbeat", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("scanning homepage for wp-heartbeat references...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    if not _HEARTBEAT_SCRIPT_RE.search(r.text):
        findings.append(Finding(
            severity="info",
            title="Heartbeat API not loaded on front-end (good)",
            evidence="No `wp-heartbeat` script reference in homepage HTML.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings
    findings.append(Finding(
        severity="low",
        title="Heartbeat API loaded on the public front-end (every visitor polls every 15 s)",
        evidence=(
            "`wp-heartbeat` is referenced in homepage HTML. Every visitor's browser "
            "polls /wp-admin/admin-ajax.php every 15 s for the duration of their "
            "session, adding persistent server load + bandwidth without a clear use "
            "on the front-end."
        ),
        remediation=(
            "Disable Heartbeat on the front-end. Either install the 'Heartbeat "
            "Control' plugin and disable on the front-end only, or in your theme's "
            "functions.php:\n\n"
            "  add_action('init', function() {\n"
            "      if (!is_admin()) wp_deregister_script('heartbeat');\n"
            "  }, 1);\n\n"
            "Keep Heartbeat enabled in wp-admin so editors don't lose autosave."
        ),
        url=ctx["target"],
    ))
    return findings
