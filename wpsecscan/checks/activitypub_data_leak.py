"""F8 (v2.8.1) — ActivityPub/Fediverse PII leak probe.

The WP ActivityPub plugin exposes per-user actor JSON at
`/@username` or `/wp-json/activitypub/1.0/users/<id>`. If author
email or other private fields leak in the actor doc, it's a
privacy regression even if the user opted into federation.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F8: probing ActivityPub actor endpoints")
    findings: list[Finding] = []
    r = await client.get("/wp-json/activitypub/1.0/users/1")
    if r is None or r.status_code != 200:
        return [Finding(severity="info",
                         title="F8: ActivityPub plugin not detected",
                         evidence="No ActivityPub actor JSON at /wp-json/activitypub/1.0/users/1",
                         remediation="No action needed.",
                         url=ctx["target"])]
    body = (r.text or "").lower()
    leaks: list[str] = []
    for marker, label in (
        ("\"email\":", "actor doc exposes email field"),
        ("@gmail.com", "email-like string in actor doc"),
        ("\"capabilities\":", "WP capabilities exposed"),
    ):
        if marker in body:
            leaks.append(label)
    if leaks:
        findings.append(Finding(severity="medium",
                                  title=f"F8: ActivityPub actor doc leaks fields ({len(leaks)})",
                                  evidence="; ".join(leaks),
                                  remediation=(
                                      "Update ActivityPub plugin >= 5.1.0. Verify privacy "
                                      "settings: Settings → ActivityPub → Profile → "
                                      "minimal-disclosure."),
                                  url=ctx["target"]))
    return findings
