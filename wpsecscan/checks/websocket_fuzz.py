"""#23 (from ZAP) — WebSocket frame fuzzer.

For sites that expose a WebSocket endpoint (auto-discovered from HTML
`new WebSocket(...)` literals), establishes a connection and sends a
small set of malformed / oversized frames to surface crashes,
authorisation slips, or content reflection.

Uses `websockets` if installed; otherwise emits an install hint.

Frames sent:
  - oversized payload (1 MB of `A`)
  - malformed JSON (`{"id":`)
  - prototype-pollution-style key (`{"__proto__":{"polluted":1}}`)
  - SQL-meta in a free-text field (`'OR'1'='1`)
  - script-tag XSS (`<svg/onload=alert(1)>`)

Aggressive only.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


_WS_URL_RE = re.compile(r'(?:new\s+WebSocket\s*\(\s*["\']|wss?://)([^"\'\s)]+)', re.IGNORECASE)


def _has_websockets() -> bool:
    try:
        import websockets  # noqa: F401
        return True
    except ImportError:
        return False


async def _discover_ws_urls(client: Client, target: str) -> list[str]:
    out: set[str] = set()
    r = await client.get("/")
    if r is None:
        return []
    parsed = urlparse(target)
    base_wsscheme = "wss" if parsed.scheme == "https" else "ws"
    for m in _WS_URL_RE.finditer(r.text or ""):
        u = m.group(1).strip().strip("'").strip('"')
        if u.startswith(("ws://", "wss://")):
            out.add(u)
        elif u.startswith("/"):
            out.add(f"{base_wsscheme}://{parsed.netloc}{u}")
    return list(out)


async def _fuzz_one(url: str) -> list[str]:
    """Returns a list of issue strings observed against one WS endpoint."""
    import websockets
    issues: list[str] = []
    frames = [
        "A" * 1_000_000,
        '{"id":',
        '{"__proto__":{"polluted":1}}',
        "'OR'1'='1",
        '<svg/onload=alert(1)>',
    ]
    try:
        async with websockets.connect(url, open_timeout=5, close_timeout=2,
                                       max_size=2_000_000) as ws:
            for f in frames:
                try:
                    await ws.send(f)
                    reply = await ws.recv()
                    if isinstance(reply, str):
                        if any(t in reply for t in ('"polluted":1', "<svg/onload",
                                                     "OR'1'='1", "SQL syntax", "ORA-")):
                            issues.append(f"reflection/echo for frame: {f[:40]!r}")
                except Exception:  # noqa: BLE001
                    continue
    except Exception as e:  # noqa: BLE001
        issues.append(f"connect/send error: {type(e).__name__}")
    return issues


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="WebSocket fuzz skipped (passive mode)",
                        evidence="Pass --aggressive to enable.", remediation="No action.",
                        url=ctx["target"])]

    if not _has_websockets():
        return [Finding(severity="info", title="WebSocket fuzz skipped (websockets not installed)",
                        evidence="Install: `pip install websockets`",
                        remediation="No action.", url=ctx["target"])]

    step("discovering WebSocket endpoints...")
    urls = await _discover_ws_urls(client, ctx["target"])
    if not urls:
        return [Finding(severity="info",
                        title="WebSocket fuzz — no endpoints found in homepage HTML",
                        evidence="No `new WebSocket(...)` / `wss?://...` literals on /.",
                        remediation="No action.", url=ctx["target"])]

    for u in urls[:3]:  # cap to 3 endpoints so one weird URL doesn't dominate
        step(f"fuzzing {u}...")
        issues = await _fuzz_one(u)
        if issues:
            findings.append(Finding(
                severity="medium",
                title=f"WebSocket {u} — {len(issues)} suspicious response(s)",
                evidence="\n".join(f"  - {i}" for i in issues),
                remediation=(
                    "Audit the WebSocket message handler. Treat every inbound message as "
                    "untrusted input — schema-validate (Ajv / jsonschema) before any DB or "
                    "filesystem operation. Add per-connection auth checks; don't assume the "
                    "Sec-WebSocket-Origin header has been validated."
                ),
                url=u,
            ))
    if not findings:
        findings.append(Finding(severity="info",
                                title=f"WebSocket fuzz — {len(urls)} endpoint(s) tested, no issues",
                                evidence=f"Endpoints: {', '.join(urls[:5])}",
                                remediation="No action.", url=ctx["target"]))
    return findings
