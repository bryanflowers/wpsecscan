from __future__ import annotations

from ..http import Client
from ..models import Finding

LISTING_PATHS = [
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-includes/",
    "wp-content/",
]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    for p in LISTING_PATHS:
        step(f"probing /{p} for directory listing...")
        r = await client.get("/" + p)
        if r is None or r.status_code != 200 or not r.text:
            continue
        body = r.text.lower()
        if ("<title>index of" in body) or ('<h1>index of' in body) or ('directory listing for' in body):
            findings.append(
                Finding(
                    severity="high",
                    title=f"Directory listing enabled at /{p}",
                    evidence=f"GET /{p} → 200 with apache-style 'Index of' page.",
                    remediation=(
                        f"Disable directory listing. Apache: add `Options -Indexes` to .htaccess. "
                        f"Nginx: ensure `autoindex` is off (default). Place an empty index.html in /{p} as belt-and-braces."
                    ),
                    url=client.url("/" + p),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No directory listings detected",
                evidence=f"Probed {len(LISTING_PATHS)} WP directories; none expose an index page.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
