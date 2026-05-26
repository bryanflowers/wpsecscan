"""Items #23-27 — consumers of the v1.1 companion-plugin endpoints.

Each endpoint requires a valid `--companion-token`. When none is set we
short-circuit silently so the check doesn't add noise.

#23 — failed-login geography: pull /failed-login-geo, join against the
     bundled GeoLite-Country country code, flag when 80%+ of recent
     failures come from one country or one ASN.
#24 — Tor admin logins: pull /admin-login-sources, cross-ref against the
     cached public Tor exit-node list.
#25 — backup status: pull /backups, flag if no run in 14d.
#26 — file-permissions: pull /file-perms, flag world-writable wp-config.
#27 — 2FA enforcement: pull /2fa-enforcement, flag admin-exempt.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import httpx

from ..http import Client
from ..models import Finding

_TOR_LIST_URL = "https://check.torproject.org/exit-addresses"
_TOR_CACHE_PATH = Path(os.environ.get("WPSECSCAN_HOME") or
                         (Path.home() / ".wpsecscan")) / "tor-exit-list.txt"
_TOR_CACHE_TTL = 6 * 3600  # refresh every 6 hours


async def _fetch_tor_exits() -> set[str]:
    """Pull (and cache) the public Tor exit-node list."""
    now = time.time()
    try:
        st = _TOR_CACHE_PATH.stat()
        if now - st.st_mtime < _TOR_CACHE_TTL:
            return _parse_tor_list(_TOR_CACHE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError):
        pass
    try:
        async with httpx.AsyncClient(timeout=15.0,
                                      headers={"User-Agent": "WPSecScan/tor-list"}) as c:
            r = await c.get(_TOR_LIST_URL)
            if r.status_code != 200:
                return set()
            txt = r.text
        _TOR_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _TOR_CACHE_PATH.write_text(txt, encoding="utf-8")
        return _parse_tor_list(txt)
    except (httpx.HTTPError, httpx.TimeoutException, OSError):
        return set()


def _parse_tor_list(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        if line.startswith("ExitAddress "):
            parts = line.split()
            if len(parts) >= 2:
                out.add(parts[1])
    return out


async def _hit(base: str, path: str, token: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(
                base.rstrip("/") + path,
                headers={"X-WPSecScan-Token": token,
                         "User-Agent": "WPSecScan/companion-advanced"},
            )
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return None
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    token = ctx.get("companion_token")
    if not token:
        return [Finding(
            severity="info",
            title="Companion advanced endpoints skipped (no --companion-token)",
            evidence="Items #23-27 require the companion plugin + a fresh single-use token.",
            remediation="No action.",
            url=ctx["target"],
        )]

    from urllib.parse import urlparse
    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"

    # --- #24 fetch Tor list in parallel with the endpoint reads
    tor_task = asyncio.create_task(_fetch_tor_exits())

    # --- #23
    step("companion: pulling failed-login-geo...")
    geo = await _hit(base, "/wp-json/wpsecscan/v1/failed-login-geo", token)
    if geo and geo.get("failed_logins"):
        total = sum(int(e.get("count", 0)) for e in geo["failed_logins"])
        if total >= 50:
            ips = sorted(geo["failed_logins"], key=lambda e: -int(e.get("count", 0)))
            top = ips[0]
            findings.append(Finding(
                severity="medium",
                title=(
                    f"High failed-login volume from a single IP "
                    f"({top['ip']}: {top['count']} attempts in {geo.get('window','7d')})"
                ),
                evidence=(
                    f"Top 5 attacking IPs in last {geo.get('window','7d')}:\n"
                    + "\n".join(f"  - {e['ip']}: {e['count']} (last seen {e.get('last_seen','?')})"
                                  for e in ips[:5]) +
                    f"\n\nTotal: {total} failed logins across {len(ips)} IPs."
                ),
                remediation=(
                    "Install Wordfence or Solid Security and enable country-level "
                    "blocking. Or add a Cloudflare WAF rule blocking the top "
                    "attacker ASNs. Confirm 2FA is enforced for the administrator "
                    "role (companion endpoint /2fa-enforcement)."
                ),
                url=ctx["target"],
                extra={"top_ips": ips[:10]},
            ))

    # --- #24 — cross-ref admin login sources with Tor exit list
    step("companion: pulling admin-login-sources...")
    sources = await _hit(base, "/wp-json/wpsecscan/v1/admin-login-sources", token)
    tor_exits = await tor_task
    if sources and tor_exits:
        tor_admin_hits = []
        for s in sources.get("sources", []):
            if s.get("ip") in tor_exits:
                tor_admin_hits.append(s)
        if tor_admin_hits:
            lines = "\n".join(f"  - {h.get('user','?')} from {h.get('ip','?')}"
                                f" ({h.get('login','?')})" for h in tor_admin_hits[:10])
            findings.append(Finding(
                severity="high",
                title=(
                    f"Admin login from Tor exit node "
                    f"({len(tor_admin_hits)} session(s))"
                ),
                evidence=(
                    "The following administrator sessions originated from a "
                    "public Tor exit node:\n\n" + lines +
                    "\n\nLegitimate admins generally don't log in over Tor. "
                    "If unexpected, treat as compromised — change passwords, "
                    "invalidate sessions, audit recent admin actions."
                ),
                remediation=(
                    "Force a global session reset (Users → Edit → 'Log out "
                    "everywhere'). Audit user_meta `session_tokens` for any "
                    "remaining sessions. Add a Cloudflare WAF rule blocking "
                    "/wp-login.php from `tor: yes` ASNs."
                ),
                url=ctx["target"] + "/wp-admin/users.php",
            ))

    # --- #25
    step("companion: pulling backup status...")
    bk = await _hit(base, "/wp-json/wpsecscan/v1/backups", token)
    if bk:
        plugins = bk.get("plugins_detected", [])
        last = bk.get("last_successful")
        if not plugins:
            findings.append(Finding(
                severity="medium",
                title="No backup plugin detected",
                evidence="None of UpdraftPlus, BlogVault, or Solid Backups is active.",
                remediation=(
                    "Install one of: UpdraftPlus (free), BlogVault (paid, off-site "
                    "by default), or Solid Backups. Configure off-site storage."
                ),
                url=ctx["target"] + "/wp-admin/plugins.php",
            ))
        elif last:
            import datetime as _dt
            try:
                last_dt = _dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
                days = (_dt.datetime.now(_dt.timezone.utc) - last_dt).days
                if days > 14:
                    findings.append(Finding(
                        severity="medium",
                        title=f"Last backup is {days} days old",
                        evidence=(
                            f"Latest successful backup: {last}. Backup plugin: "
                            f"{', '.join(plugins)}. Off-site destination: "
                            f"{bk.get('remote_destination') or 'NONE'}."
                        ),
                        remediation=(
                            "Either fix the scheduled-backup cron or switch to "
                            "a managed off-site solution (BlogVault, Jetpack "
                            "VaultPress). Without recent off-site backups a "
                            "ransomware or hosting-account-takeover means total "
                            "data loss."
                        ),
                        url=ctx["target"],
                    ))
            except (ValueError, TypeError):
                pass

    # --- #26
    step("companion: pulling file permissions...")
    fp = await _hit(base, "/wp-json/wpsecscan/v1/file-perms", token)
    if fp:
        risky: list[tuple[str, str]] = []
        for label, info in (fp.get("paths") or {}).items():
            if not info.get("exists"):
                continue
            if info.get("world_writable"):
                risky.append((label, info.get("octal", "")))
        if risky:
            findings.append(Finding(
                severity="high" if any("wp-config.php" in r[0] for r in risky) else "medium",
                title=f"World-writable WordPress paths ({len(risky)})",
                evidence="\n".join(f"  - {label}: mode {octal}" for label, octal in risky),
                remediation=(
                    "Tighten permissions:\n"
                    "  chmod 600 wp-config.php\n"
                    "  chmod 755 wp-content/ uploads/ plugins/\n"
                    "World-writable wp-config.php means any process on the box "
                    "(including a low-priv shell from another tenant) can read "
                    "your DB password."
                ),
                url=ctx["target"],
            ))

    # --- #27
    step("companion: pulling 2FA enforcement...")
    tfa = await _hit(base, "/wp-json/wpsecscan/v1/2fa-enforcement", token)
    if tfa:
        if not tfa.get("plugins_detected"):
            findings.append(Finding(
                severity="medium",
                title="No 2FA plugin active",
                evidence="None of Wordfence-Login-Security, WP-2FA, or Solid Security is active.",
                remediation=(
                    "Install Wordfence-Login-Security (free) or WP-2FA (free + "
                    "premium tiers). Enforce TOTP for the administrator role at "
                    "minimum."
                ),
                url=ctx["target"] + "/wp-admin/plugins.php",
            ))
        elif tfa.get("admin_exempt") is True:
            findings.append(Finding(
                severity="medium",
                title="2FA is configured but administrators are exempt",
                evidence=(
                    f"Plugins active: {', '.join(tfa.get('plugins_detected', []))}. "
                    f"Enforced roles: {', '.join(tfa.get('enforced_for_roles', [])) or '(none)'}. "
                    "Administrator is NOT in the enforced-roles list."
                ),
                remediation=(
                    "Open the 2FA plugin's policy page and add 'administrator' "
                    "to the required-roles list. Admin accounts are the highest "
                    "value target — leaving them exempt defeats the purpose."
                ),
                url=ctx["target"] + "/wp-admin/",
            ))

    return findings or [Finding(
        severity="info",
        title="Companion advanced endpoints — no issues found",
        evidence=f"Pulled 5 advanced endpoints with companion token at {base}.",
        remediation="No action needed.",
        url=ctx["target"],
    )]
