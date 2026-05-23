"""HaveIBeenPwned username breach lookup.

Consumes ctx['shared']['users'] (populated by checks/users.py).
Without --hibp-token: emits info findings with HIBP URLs the user can check manually.
With --hibp-token: queries the breachedaccount API and reports breaches found.
"""
from __future__ import annotations

import asyncio

import httpx

from ..http import Client
from ..models import Finding

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}?truncateResponse=false"
MAX_LOOKUPS_PER_SCAN = 5


async def _query_hibp(token: str, account: str) -> tuple[int, list[dict]]:
    """Returns (status_code, list of breach dicts)."""
    headers = {
        "hibp-api-key": token,
        "User-Agent": "WPSecScan/1.0",
    }
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.get(HIBP_API.format(account=account), headers=headers)
        if r.status_code == 200:
            try:
                return 200, r.json()
            except ValueError:
                return 200, []
        return r.status_code, []


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    users: list[str] = sorted(ctx.get("shared", {}).get("users") or [])
    token = ctx.get("hibp_token")

    if not users:
        findings.append(
            Finding(
                severity="info",
                title="HIBP lookup skipped — no usernames discovered",
                evidence="The user-enumeration check did not find any usernames to look up.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    if not token:
        # No token — just surface HIBP URLs for manual review
        lines = "\n".join(
            f"  - {u}: https://haveibeenpwned.com/account/{u}" for u in users[:10]
        )
        findings.append(
            Finding(
                severity="info",
                title=f"{len(users)} username(s) discoverable — check HIBP manually",
                evidence=(
                    f"Discovered usernames:\n{lines}\n\n"
                    "Without a HIBP API token we can't query breaches automatically. "
                    "Visit the links above (or pass --hibp-token <key>) to check each account."
                ),
                remediation=(
                    "Force a password rotation for any user whose account email appears in known breaches. "
                    "Buy a HIBP key at haveibeenpwned.com/API/Key (~$3.95/mo) to automate this."
                ),
                url=ctx["target"],
                extra={"next_steps": [f"# Manual lookup: https://haveibeenpwned.com/account/{users[0]}"]},
            )
        )
        return findings

    # Token present — do real lookups, rate-limited to 5 per scan
    breached: list[tuple[str, list[dict]]] = []
    queried = 0
    for u in users:
        if queried >= MAX_LOOKUPS_PER_SCAN:
            break
        step(f"HIBP lookup for {u}...")
        # HIBP free tier: 1 request per ~1.5s. Pace ourselves.
        if queried > 0:
            await asyncio.sleep(1.7)
        queried += 1
        try:
            status, breaches = await _query_hibp(token, u)
        except httpx.HTTPError as e:
            findings.append(
                Finding(
                    severity="info",
                    title=f"HIBP lookup network error for '{u}'",
                    evidence=f"{type(e).__name__}: {e}",
                    remediation="Re-run later or check token quota.",
                )
            )
            continue
        if status == 200 and breaches:
            breached.append((u, breaches))
        elif status == 404:
            pass  # not breached
        elif status == 401:
            findings.append(
                Finding(
                    severity="info",
                    title="HIBP token is invalid or has no quota",
                    evidence="API returned 401 — verify token at haveibeenpwned.com/API/Key.",
                    remediation="Provide a valid --hibp-token.",
                )
            )
            return findings
        elif status == 429:
            findings.append(
                Finding(
                    severity="info",
                    title="HIBP rate-limited — aborting remaining lookups",
                    evidence=f"Got HTTP 429 after {queried} lookup(s).",
                    remediation="Wait a minute and re-run.",
                )
            )
            return findings

    for u, breaches in breached:
        names = ", ".join(b.get("Name", "?") for b in breaches[:8])
        findings.append(
            Finding(
                severity="medium",
                title=f"User '{u}' appears in {len(breaches)} known breach(es)",
                evidence=(
                    f"HIBP breaches: {names}{' …' if len(breaches) > 8 else ''}\n"
                    "If this user reuses the breached password anywhere, the WP account is at risk."
                ),
                remediation=(
                    f"Force '{u}' to reset their password. Encourage password manager + 2FA. "
                    "Consider mandatory rotation for any admin in this list."
                ),
                url=f"https://haveibeenpwned.com/account/{u}",
            )
        )

    if not breached:
        findings.append(
            Finding(
                severity="info",
                title=f"No HIBP breaches found for {queried} discovered username(s)",
                evidence=f"Queried HIBP for: {', '.join(users[:queried])}",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
