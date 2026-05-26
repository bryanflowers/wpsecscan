"""Query Certificate-Transparency logs for unexpected recent cert issuances.

Every public certificate must be logged to a Certificate Transparency
(CT) log within hours of issuance. crt.sh aggregates these logs and
exposes a search API. Looking for `*.target.com` issuances in the last
30 days catches:
  - shadow-IT subdomains the site owner didn't create
  - subdomain takeovers that have already been TLS-provisioned
  - phishing-prep domains (typosquats issued under your name)
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


async def _crtsh_query(domain: str) -> list[dict]:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return []
    try:
        async with httpx.AsyncClient(timeout=30.0,
                                     headers={"User-Agent": "WPSecScan/ct"}) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    except (httpx.HTTPError, OSError):
        return []
    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _parse_dt(s: str) -> datetime | None:
    """crt.sh dates look like '2026-04-15T12:34:56'."""
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    if not host or host.count(".") < 1:
        return findings
    apex = ".".join(host.split(".")[-2:])
    step(f"querying crt.sh for {apex} certs issued in last 30 days...")
    rows = await _crtsh_query(apex)
    if not rows:
        return findings
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent: list[dict] = []
    for row in rows[:500]:
        if not isinstance(row, dict):
            continue
        dt = _parse_dt(row.get("entry_timestamp", "") or row.get("not_before", ""))
        if dt and dt >= cutoff:
            recent.append({
                "name": row.get("name_value", "")[:200],
                "issuer": row.get("issuer_name", "")[:100],
                "logged_at": dt.isoformat(),
            })
    if not recent:
        return findings
    # Deduplicate by name
    seen_names: set[str] = set()
    uniq = []
    for r in recent:
        n = r["name"]
        if n not in seen_names:
            seen_names.add(n)
            uniq.append(r)
    sev = "info"
    if len(uniq) >= 5:
        sev = "low"
    lines = "\n".join(f"  - {r['logged_at'][:10]}  {r['name'][:80]}  ({r['issuer'][:30]})"
                      for r in uniq[:15])
    findings.append(Finding(
        severity=sev,
        title=f"CT logs show {len(uniq)} cert(s) for *.{apex} issued in last 30 days",
        evidence=(
            f"crt.sh returned {len(uniq)} distinct certificate names issued "
            f"in the last 30 days for `*.{apex}`:\n{lines}"
            + (f"\n  ... and {len(uniq) - 15} more" if len(uniq) > 15 else "")
            + "\n\nVerify each name is a subdomain you intentionally provisioned. "
              "Unexpected entries can indicate:\n"
              "  - shadow-IT or rogue-employee deployments\n"
              "  - a subdomain takeover where the attacker has provisioned a "
              "Let's Encrypt cert on a dangling-CNAME target\n"
              "  - phishing-prep typosquats from a free issuer (rare; CAs "
              "validate apex ownership, but worth a sanity check)."
        ),
        remediation=(
            f"Audit each entry against your records of intentional subdomain "
            "creation. Any unrecognised name should be investigated immediately. "
            "Set up an automated CT-monitor (Cert Spotter, Facebook CT API, or "
            "self-hosted crt.sh polling) to alert on new entries in near-real-time."
        ),
        url=f"https://crt.sh/?q=%25.{apex}",
        extra={"recent_cert_names": [r["name"] for r in uniq[:50]]},
    ))
    return findings
