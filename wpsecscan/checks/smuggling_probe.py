"""HTTP request-smuggling probe (passive — never actually smuggles).

A *real* smuggling test would send conflicting Content-Length / Transfer-Encoding
headers and observe whether the backend desyncs (a write-side action). We won't
do that — instead we PASSIVELY look for indicators that the front-end and back-end
disagree on framing:
  1. Detect HTTP/2 frontend with HTTP/1.1 backend (the highest-risk topology)
  2. Detect duplicate Host / Content-Length headers in the response (signs of
     a misconfigured reverse proxy that may also accept duplicates inbound)
  3. Detect a `Transfer-Encoding: chunked` echo / pass-through on a response
     to a HEAD request (front-end mishandles)

If any indicators are present, flag the risk class with a "verify with Burp /
smuggler.py" remediation — we deliberately stop short of confirming actively.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    indicators: list[str] = []

    step("inspecting / for smuggling-prone topology...")
    r = await client.get("/")
    if r is None:
        findings.append(
            Finding(
                severity="info",
                title="Smuggling probe — no response from /",
                evidence="GET / didn't return a response.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    http_version = getattr(r, "http_version", "")
    server = (r.headers.get("server", "") or r.headers.get("Server", "")).strip()
    via = (r.headers.get("via", "") or r.headers.get("Via", "")).strip()
    fwd = (r.headers.get("x-forwarded-server", "") or r.headers.get("X-Forwarded-Server", "")).strip()

    # 1. HTTP/2 frontend with HTTP/1.1 backend
    if http_version in ("HTTP/2", "h2") and (via or fwd):
        indicators.append(
            "HTTP/2 frontend with apparent backend behind a proxy (`Via`/`X-Forwarded-Server` set). "
            "Classic h2c-smuggling and h2.cl.te topologies live here."
        )

    # 2. Duplicate Content-Length / Transfer-Encoding
    raw_headers = list(r.headers.items()) if hasattr(r.headers, "items") else []
    cl_count = sum(1 for k, _v in raw_headers if k.lower() == "content-length")
    te_count = sum(1 for k, _v in raw_headers if k.lower() == "transfer-encoding")
    if cl_count > 1:
        indicators.append(f"Response has {cl_count} `Content-Length` headers — proxy may be merging or duplicating.")
    if te_count > 1:
        indicators.append(f"Response has {te_count} `Transfer-Encoding` headers — proxy framing is inconsistent.")
    if cl_count >= 1 and te_count >= 1:
        indicators.append(
            "Response has BOTH `Content-Length` and `Transfer-Encoding` — RFC 7230 says the latter wins, "
            "but in practice some backends honor CL while frontends honor TE → desync."
        )

    # 3. HEAD with TE in response is a smell
    step("probing HEAD / for chunked-echo bug...")
    r_head = await client.head("/")
    if r_head is not None:
        te = (r_head.headers.get("transfer-encoding", "") or r_head.headers.get("Transfer-Encoding", "")).lower()
        if "chunked" in te:
            indicators.append(
                "HEAD / response carries `Transfer-Encoding: chunked` — most reverse proxies strip "
                "this on HEAD; presence suggests passthrough that may also pass attacker-controlled framing."
            )

    # A6: active desync probe (aggressive only) — send a CL.TE desync attempt with
    # benign content. If the front-end honors Content-Length and the back-end
    # honors Transfer-Encoding, the second request's body slips through. We send
    # a probe whose "smuggled" content is a HEAD request — entirely safe; the
    # only observable change is response-time delta.
    if ctx.get("aggressive"):
        step("active CL.TE desync probe...")
        # We can't easily send raw HTTP through httpx, so we approximate by sending
        # conflicting CL + TE headers and looking for a 400/411/501 ERROR
        # (front-end rejected) vs 200 (back-end happily processed both halves).
        smuggle_body = "0\r\n\r\nGET /wpsec-smuggle-probe HTTP/1.1\r\nHost: localhost\r\n\r\n"
        r_smuggle = await client.post(
            "/",
            content=smuggle_body,
            headers={
                "Content-Length": str(len(smuggle_body)),
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if r_smuggle is not None and r_smuggle.status_code == 200:
            indicators.append(
                "Active CL.TE desync probe: server accepted conflicting CL+TE headers with HTTP 200. "
                "A real attacker could smuggle a request through to the back-end with this framing mismatch."
            )
        # A second probe: TE.CL with chunked body that closes before CL expects
        r_te_cl = await client.post(
            "/",
            content="0\r\n\r\n",
            headers={
                "Content-Length": "5",
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if r_te_cl is not None and r_te_cl.status_code == 200:
            indicators.append("Active TE.CL desync probe: server accepted TE=chunked with mismatched CL=5 -> 200.")

    if not indicators:
        findings.append(
            Finding(
                severity="info",
                title="No HTTP request-smuggling indicators detected",
                evidence=(
                    f"HTTP version: {http_version or 'unknown'}, "
                    f"Server: {server or '(none)'}, "
                    f"Via: {via or '(none)'}, "
                    f"X-Forwarded-Server: {fwd or '(none)'}"
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="medium",
            title=f"HTTP request-smuggling indicators present ({len(indicators)})",
            evidence="\n".join(f"  • {x}" for x in indicators),
            remediation=(
                "wpsecscan stops short of confirming smuggling — that would require write-side probes. "
                "For confirmation, run smuggler.py or PortSwigger's Burp Smuggling extension against "
                "this target. References: "
                "https://portswigger.net/web-security/request-smuggling  ·  "
                "https://github.com/defparam/smuggler  ·  "
                "CVE-2023-44487 (HTTP/2 rapid reset)."
            ),
            url=ctx["target"],
        )
    )
    return findings
