"""Reflected XSS probes — uses a benign marker payload with a per-scan nonce.

Does not execute any JavaScript. Detection is purely structural: did our angle
brackets and quotes survive into the response unescaped?
"""
from __future__ import annotations

import secrets

from ..http import Client
from ..models import Finding
from ..prove import build_replay_curl

# (param_name, description)
TARGETS = (
    ("s",            "search ?s="),
    ("p",            "post ?p="),
    ("author_name",  "author_name ?author_name="),
    ("post_type",    "post_type ?post_type="),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    nonce = secrets.token_hex(4)
    payload = f"<wpsx{nonce}>\"'"
    marker_raw = f"<wpsx{nonce}>"
    marker_attr = f"wpsx{nonce}"

    for param, desc in TARGETS:
        step(f"probing {desc} for reflected XSS...")
        r = await client.get("/", params={param: payload})
        if r is None or not r.text:
            continue
        body = r.text
        if marker_raw in body:
            url = client.url(f"/?{param}={payload}")
            replay = build_replay_curl("GET", client.url("/"), params={param: payload})
            findings.append(
                Finding(
                    severity="high",
                    title=f"Reflected payload (angle brackets unescaped) in {desc}",
                    evidence=(
                        f"GET /?{param}={payload} -> {r.status_code}\n"
                        f"  Marker {marker_raw} appears verbatim in response body.\n"
                        "Unescaped < and > characters in HTML output are the precondition for reflected XSS."
                    ),
                    remediation=(
                        "Escape all user-controlled output with esc_html(), esc_attr(), or wp_kses() "
                        "depending on context. For search query reflection specifically, use the_search_query(). "
                        "Audit any plugin/theme rendering this parameter."
                    ),
                    url=url,
                    extra={
                        "provable": True,
                        "prover": "xss_reflected",
                        "param": param,
                        "payload": payload,
                        "marker": marker_raw,
                        "baseline_path": "/",
                        "replay": replay,
                        "next_steps": [
                            "# Confirm impact manually — try a real <script>alert(1)</script> payload in a browser dev tool",
                            "# For Burp users: send the request to Repeater, then to Intruder for parameter fuzzing",
                        ],
                    },
                )
            )
        elif marker_attr in body:
            # Reflection happened but brackets were escaped — still worth flagging as low risk.
            findings.append(
                Finding(
                    severity="low",
                    title=f"Parameter '{param}' is reflected (brackets escaped)",
                    evidence=(
                        f"Marker 'wpsx{nonce}' reflected; angle brackets appear escaped. "
                        "Low risk on its own, but quote-context bugs can still enable attribute-break XSS."
                    ),
                    remediation="Ensure attribute values in PHP templates are wrapped with esc_attr().",
                    url=client.url(f"/?{param}={payload}"),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No reflected XSS markers detected on tested parameters",
                evidence=f"Probed {len(TARGETS)} parameters with a unique nonce payload; none reflected unescaped.",
                remediation="No action needed for the tested endpoints.",
                url=ctx["target"],
            )
        )
    return findings
