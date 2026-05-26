"""CSP `report-uri` / `report-to` endpoint health check.

A site with a Content-Security-Policy that points its violation reports
at a broken endpoint (404/5xx) gets zero visibility into CSP violations,
defeating the monitoring value of having a policy at all. This check
extracts the endpoint URL(s) from the CSP header and does a single HEAD
request to each to verify the reporting destination is reachable.
"""
from __future__ import annotations

import re

import httpx

from ..http import Client
from ..models import Finding


_REPORT_URI_RE = re.compile(r"report-uri\s+([^;]+)", re.IGNORECASE)
_REPORT_TO_RE = re.compile(r"report-to\s+([^;]+)", re.IGNORECASE)


async def _head_status(url: str, timeout: float = 8.0) -> int | None:
    """Return the HTTP status of a HEAD to `url`, or None on connection error."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.head(url)
            return r.status_code
    except (httpx.HTTPError, OSError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    r = await client.get("/")
    if r is None:
        return findings
    csp = r.headers.get("Content-Security-Policy") or r.headers.get("content-security-policy") or ""
    if not csp:
        return findings  # not our check to flag — csp.py handles "missing CSP"

    endpoints: list[tuple[str, str]] = []  # (kind, url)
    for m in _REPORT_URI_RE.finditer(csp):
        for u in m.group(1).split():
            u = u.strip()
            if u.startswith(("http://", "https://", "/")):
                endpoints.append(("report-uri", u))
    for m in _REPORT_TO_RE.finditer(csp):
        # report-to is a group name, not a URL. Only flag if it's the
        # legacy report-uri-style URL form.
        for u in m.group(1).split():
            u = u.strip()
            if u.startswith(("http://", "https://")):
                endpoints.append(("report-to", u))

    if not endpoints:
        return findings  # no reporting configured — fine

    for kind, ep in endpoints:
        step(f"probing CSP {kind} endpoint: {ep}")
        # Resolve relative URLs against the scan target
        if ep.startswith("/"):
            target_url = client.url(ep)
        else:
            target_url = ep
        status = await _head_status(target_url)
        if status is None:
            findings.append(Finding(
                severity="medium",
                title=f"CSP {kind} endpoint is unreachable",
                evidence=f"HEAD {target_url} → connection error.\nCSP value: {csp[:200]}",
                remediation=(
                    "Either remove the broken reporting directive from your CSP, "
                    "or fix the endpoint. A CSP whose violation reports go nowhere "
                    "is a CSP whose monitoring value is zero — you have no "
                    "visibility into real-world policy hits."
                ),
                url=ctx["target"],
            ))
        elif status >= 400:
            findings.append(Finding(
                severity="medium",
                title=f"CSP {kind} endpoint returns HTTP {status}",
                evidence=f"HEAD {target_url} → {status}\nCSP value: {csp[:200]}",
                remediation=(
                    f"The endpoint declared by your CSP `{kind}` directive returns "
                    f"HTTP {status} — violation reports will be dropped. Verify "
                    "the endpoint accepts POST requests (`report-uri`) or the "
                    "Reporting API endpoint group is registered correctly."
                ),
                url=ctx["target"],
            ))
        else:
            findings.append(Finding(
                severity="info",
                title=f"CSP {kind} endpoint reachable ({status})",
                evidence=f"HEAD {target_url} → {status}",
                remediation="No action.",
                url=ctx["target"],
            ))
    return findings
