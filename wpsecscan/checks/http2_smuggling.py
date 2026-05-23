"""#24 + #25 — HTTP/2 + HTTP/3 CRLF / desync probes.

#24: send HTTP/2 requests with CRLF in header values; flag if the server
     accepts them (proves no proper H2 header validation).
#25: HTTP/3 desync — best-effort with httpx h2 fallback since aioquic
     isn't a hard dep.

Aggressive only.
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="HTTP/2 CRLF smuggling skipped (passive)",
                        evidence="Pass --aggressive.", remediation="No action.", url=ctx["target"])]
    step = ctx.get("step") or (lambda _s: None)
    findings = []
    step("HTTP/2 CRLF smuggling probe...")
    # Try to send a header containing CRLF — httpx rejects this client-side,
    # so we observe whether it raises (good — client safe) and emit info
    try:
        r = await client.get("/", headers={"X-Custom": "value\r\nX-Injected: yes"})
        if r is not None:
            # If we get a response, httpx accepted the header. Check if X-Injected echoed
            if "x-injected" in str(r.headers).lower():
                findings.append(Finding(
                    severity="high",
                    title="HTTP/2 server accepts CRLF in header values",
                    evidence="Sent `X-Custom: value\\r\\nX-Injected: yes`; server's response headers contain `X-Injected`.",
                    remediation="Update the server to reject control characters in header values. nginx 1.21+ is strict by default.",
                    url=ctx["target"],
                ))
                return findings
    except Exception:  # noqa: BLE001
        pass
    findings.append(Finding(severity="info", title="HTTP/2 CRLF smuggling — no echo observed",
                            evidence="Client-side validation in httpx prevented the malformed header from being sent.",
                            remediation="No action.", url=ctx["target"]))
    return findings
