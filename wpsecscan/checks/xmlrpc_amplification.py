"""Measure xmlrpc.php system.multicall response amplification.

Existing xmlrpc_deep flags multicall availability. This one quantifies it:
one POST with 50 nested wp.getUsersBlogs calls. Compute the
response-bytes / request-bytes ratio. >100x = high (concrete DoS math).
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


_PAYLOAD_TEMPLATE = """<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName>
<params><param><value><array><data>
{calls}
</data></array></value></param></params>
</methodCall>"""

_CALL = """<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>x</string></value>
<value><string>x</string></value>
</data></array></value></member>
</struct></value>"""


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    # Pre-check: is /xmlrpc.php reachable?
    pre = await client.get("/xmlrpc.php")
    if pre is None or pre.status_code != 405 and pre.status_code != 200:
        return findings  # not WP / disabled
    payload = _PAYLOAD_TEMPLATE.format(calls="\n".join([_CALL] * 50))
    req_bytes = len(payload.encode("utf-8"))
    step(f"POSTing 50-call system.multicall ({req_bytes} bytes)...")
    r = await client.post("/xmlrpc.php", content=payload,
                          headers={"Content-Type": "text/xml"})
    if r is None or r.status_code != 200:
        return findings
    resp_bytes = len(r.content or b"")
    if resp_bytes < req_bytes * 5:
        return findings  # not meaningfully amplifying
    ratio = resp_bytes / max(req_bytes, 1)
    sev = "high" if ratio >= 100 else ("medium" if ratio >= 20 else "low")
    findings.append(Finding(
        severity=sev,
        title=f"xmlrpc.php system.multicall amplifies {ratio:.0f}x (50-call batch)",
        evidence=(
            f"POST /xmlrpc.php (50 wp.getUsersBlogs calls, {req_bytes} bytes) → "
            f"{resp_bytes} bytes response. Amplification factor: {ratio:.1f}x.\n\n"
            "Each multicall request packs N method invocations into one HTTP "
            "request; the server returns N response bodies back. Even with auth "
            "errors, each method generates a verbose fault structure.\n\n"
            f"Concrete attack math: at {ratio:.0f}x amplification, an attacker "
            "with 1 Mbit/s upload can deliver up to "
            f"{(ratio):.0f} Mbit/s of response bandwidth to your server's outbound "
            "interface — a cheap bandwidth-bill DoS."
        ),
        remediation=(
            "1. Disable XML-RPC entirely if you don't use the Jetpack mobile-app "
            "or remote-publishing workflows. In wp-config.php:\n"
            "   add_filter('xmlrpc_enabled', '__return_false');\n"
            "2. If XML-RPC must stay, disable system.multicall specifically:\n"
            "   add_filter('xmlrpc_methods', function($m) {\n"
            "       unset($m['system.multicall']); return $m;\n"
            "   });\n"
            "3. Block /xmlrpc.php at the web server when feasible — `nginx: "
            "location = /xmlrpc.php { deny all; }`."
        ),
        url=client.url("/xmlrpc.php"),
        extra={"amplification_ratio": round(ratio, 1)},
    ))
    return findings
