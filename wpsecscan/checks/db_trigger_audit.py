"""Database trigger audit (companion-plugin assisted).

Round-64 #53 — attackers sometimes install MySQL triggers as a stealth
persistence mechanism (fires on a normal write, runs arbitrary SQL). We
can't enumerate triggers remotely without DB access; the companion
plugin exposes `/wp-json/wpsecscan-companion/v1/triggers` which returns
the trigger list. Without the companion, this check is a no-op +
recommends installing it.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


# Known-bad trigger callbacks that indicate webshell-style persistence.
_SUSPICIOUS_TRIGGER_PATTERNS = (
    "system(",
    "exec(",
    "load_file(",
    "outfile",
    "into dumpfile",
    "sys_exec",
    "lib_mysqludf",
    "base64_decode",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("querying companion plugin for DB triggers...")
    r = await client.get("/wp-json/wpsecscan-companion/v1/triggers")
    if r is None or r.status_code == 404:
        # Companion plugin not installed — silent. The plugin_outreach check
        # already recommends installing it.
        return findings
    if r.status_code in (401, 403):
        findings.append(
            Finding(
                severity="info",
                title="Companion plugin present but DB-trigger endpoint requires auth",
                evidence=f"GET /wp-json/wpsecscan-companion/v1/triggers -> {r.status_code}",
                remediation="Configure the companion plugin's shared secret in wpsecscan sites config so this check can authenticate.",
                url=client.url("/wp-json/wpsecscan-companion/v1/triggers"),
            )
        )
        return findings
    if r.status_code != 200:
        return findings

    try:
        data = r.json()
    except (ValueError, TypeError):
        return findings

    triggers = data.get("triggers", []) if isinstance(data, dict) else []
    if not triggers:
        findings.append(
            Finding(
                severity="info",
                title="No database triggers installed (clean)",
                evidence=f"Companion returned {len(triggers)} triggers",
                remediation="Re-run periodically; triggers can be installed via stolen DB creds even without WP code access.",
                url=client.url("/wp-json/wpsecscan-companion/v1/triggers"),
            )
        )
        return findings

    suspicious = []
    for t in triggers:
        body = (t.get("statement", "") or "").lower()
        hits = [p for p in _SUSPICIOUS_TRIGGER_PATTERNS if p in body]
        if hits:
            suspicious.append((t.get("name", "?"), hits))

    if suspicious:
        for name, hits in suspicious:
            findings.append(
                Finding(
                    severity="critical",
                    title=f"Suspicious MySQL trigger: {name}",
                    evidence=f"Trigger body contains: {', '.join(hits)}",
                    remediation=(
                        "This trigger fires on a normal table write and may be running arbitrary code.\n"
                        "Run in MySQL:\n"
                        "  SHOW TRIGGERS;\n"
                        "  DROP TRIGGER <name>;\n"
                        "Then audit for the entry-point that allowed an attacker to install the trigger (stolen DB creds, SQLi)."
                    ),
                    url=client.url("/wp-json/wpsecscan-companion/v1/triggers"),
                    extra={"trigger_name": name, "hit_patterns": hits},
                )
            )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"{len(triggers)} DB trigger(s) — none matched malicious patterns",
                evidence=f"Triggers: {', '.join(t.get('name', '?') for t in triggers[:10])}",
                remediation="Triggers may be legitimate; review each in MySQL: SHOW CREATE TRIGGER <name>.",
                url=client.url("/wp-json/wpsecscan-companion/v1/triggers"),
            )
        )
    return findings
