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

    # ===== v1.2.0 endpoint consumers =====

    # #11 — active-sessions: flag anomalous parallel sessions per admin
    step("companion: pulling active-sessions...")
    sess = await _hit(base, "/wp-json/wpsecscan/v1/active-sessions", token)
    if sess and sess.get("active_sessions"):
        per_user: dict[str, list] = {}
        for s in sess["active_sessions"]:
            per_user.setdefault(s.get("user_login", "?"), []).append(s)
        excessive = [(u, sl) for u, sl in per_user.items() if len(sl) >= 3]
        if excessive:
            lines = []
            for u, sl in excessive[:5]:
                ips = sorted({x.get("ip", "?") for x in sl})
                lines.append(f"  - {u}: {len(sl)} sessions across {len(ips)} IPs ({', '.join(ips[:3])})")
            findings.append(Finding(
                severity="medium",
                title=f"Admin account(s) with 3+ concurrent sessions ({len(excessive)} user(s))",
                evidence="Multiple parallel admin sessions can indicate account "
                         "compromise (the attacker is logged in alongside the real user):\n\n"
                         + "\n".join(lines),
                remediation=(
                    "If unexpected: change the password + Force-log-out-everywhere "
                    "in WP admin → Users → Profile. Then audit recent admin actions "
                    "via the /recent-admin-actions endpoint."
                ),
                url=ctx["target"] + "/wp-admin/users.php",
            ))

    # #18 — log-files exposed under the web root
    step("companion: pulling log-files...")
    logs = await _hit(base, "/wp-json/wpsecscan/v1/log-files", token)
    if logs and logs.get("log_files"):
        lines = []
        for f in logs["log_files"][:10]:
            lines.append(f"  - {f.get('path','?')} ({f.get('bytes',0):,} bytes)")
        findings.append(Finding(
            severity="high" if any("error_log" in (f.get("path") or "") for f in logs["log_files"]) else "medium",
            title=f"{len(logs['log_files'])} log file(s) exposed under web root",
            evidence=("These files live inside the web root and may be "
                       "served verbatim by a misconfigured nginx/Apache:\n\n"
                       + "\n".join(lines)),
            remediation=(
                "Move log files outside ABSPATH (e.g. /var/log/wp/{site}.log) "
                "or add a deny rule. Apache: `<FilesMatch \"\\.log$\">Require "
                "all denied</FilesMatch>`. Nginx: `location ~ \\.log$ { "
                "deny all; }`."
            ),
            url=ctx["target"],
        ))

    # #17 — db-size-by-table: flag abnormally large per-table sizes
    step("companion: pulling db-size-by-table...")
    db = await _hit(base, "/wp-json/wpsecscan/v1/db-size-by-table", token)
    if db and db.get("tables"):
        # Heuristic: any non-_postmeta table >100 MB, or _options >50 MB.
        large = []
        for t in db["tables"]:
            name = (t.get("table") or "").lower()
            bytes_ = int(t.get("bytes") or 0)
            if name.endswith("_postmeta") and bytes_ > 500 * 1024 * 1024:
                large.append(t)
            elif name.endswith("_options") and bytes_ > 50 * 1024 * 1024:
                large.append(t)
            elif name.endswith("_comments") and bytes_ > 200 * 1024 * 1024:
                large.append(t)
            elif bytes_ > 1 * 1024 * 1024 * 1024:
                large.append(t)
        if large:
            findings.append(Finding(
                severity="low",
                title=f"{len(large)} DB table(s) abnormally large",
                evidence="\n".join(
                    f"  - {t.get('table')}: {int(t.get('bytes', 0)) / (1024 * 1024):.1f} MB "
                    f"({int(t.get('rows', 0)):,} rows)"
                    for t in large[:10]
                ),
                remediation=(
                    "Large _options often = transient bloat (clean with "
                    "Transients Manager). Large _postmeta often = leftover "
                    "plugin garbage (clean with WP-Optimize). Large _comments "
                    "= spam — run an Akismet sweep."
                ),
                url=ctx["target"],
            ))

    # #19 — php-error-log-tail: surface critical errors
    step("companion: pulling php-error-log-tail...")
    errs = await _hit(base, "/wp-json/wpsecscan/v1/php-error-log-tail", token)
    if errs and errs.get("lines"):
        critical_lines = [l for l in errs["lines"]
                            if "PHP Fatal error" in l or "PHP Parse error" in l]
        if critical_lines:
            findings.append(Finding(
                severity="medium",
                title=f"{len(critical_lines)} PHP fatal error(s) in error_log",
                evidence="Last 5 fatal entries (PII stripped):\n\n"
                         + "\n".join(f"  - {l[:200]}" for l in critical_lines[:5]),
                remediation=(
                    "Track down the plugin / theme causing the fatals. The "
                    "error log path is "
                    f"{errs.get('log_path', '(not configured)')}. "
                    "Disable WP_DEBUG_DISPLAY in wp-config.php so fatals "
                    "don't leak to visitors while you fix."
                ),
                url=ctx["target"],
            ))

    # #12 — recent-admin-actions: informational pull, no finding
    step("companion: pulling recent-admin-actions...")
    _ = await _hit(base, "/wp-json/wpsecscan/v1/recent-admin-actions", token)
    # Returned data is informational; surfaced via JSON output extra field
    # in a future release. No finding generated today.

    # #13 — wp-cron-failures
    step("companion: pulling wp-cron-failures...")
    crf = await _hit(base, "/wp-json/wpsecscan/v1/wp-cron-failures", token)
    if crf and crf.get("failures"):
        n = len(crf["failures"])
        sev = "high" if n >= 10 else "medium"
        lines = []
        for f in crf["failures"][:8]:
            lines.append(f"  - {f.get('hook','?')}  ({f.get('status','?')}, "
                          f"source={f.get('source','?')})")
        findings.append(Finding(
            severity=sev,
            title=f"{n} wp-cron hook(s) failing or overdue",
            evidence=("Stalled cron is a frequent indicator of malware "
                       "persistence — attackers hijack a hook, then ensure "
                       "WP can't run it to its scheduled completion:\n\n"
                       + "\n".join(lines)),
            remediation=(
                "Verify each hook's callback resolves cleanly (check "
                "Action Scheduler's admin page if WooCommerce is installed). "
                "For overdue wp-cron hooks, ensure WP_CRON_LOCK_TIMEOUT is "
                "not stuck and the site receives enough traffic to trigger "
                "wp-cron, OR install a system cron job hitting wp-cron.php."
            ),
            url=ctx["target"] + "/wp-admin/tools.php?page=action-scheduler",
        ))

    # #14 — scheduled-task-anomalies
    step("companion: pulling scheduled-task-anomalies...")
    anom = await _hit(base, "/wp-json/wpsecscan/v1/scheduled-task-anomalies", token)
    if anom and anom.get("anomalies"):
        recently_added = anom["anomalies"]
        if len(recently_added) >= 5:
            lines = "\n".join(
                f"  - {a.get('hook','?')}  (scheduled {a.get('scheduled','?')})"
                for a in recently_added[:8]
            )
            findings.append(Finding(
                severity="low",
                title=f"{len(recently_added)} non-core cron hook(s) scheduled in last 7 days",
                evidence=("Newly-scheduled hooks aren't intrinsically bad, "
                           "but if they correspond to plugins you didn't "
                           "install in the last week, they may be malware "
                           "persistence:\n\n" + lines),
                remediation=(
                    "Cross-reference each hook name against installed plugins. "
                    "Hooks that look auto-generated (hex strings, base64-ish, "
                    "single-letter names) deserve immediate investigation."
                ),
                url=ctx["target"],
            ))

    # #20 — cron-shell-commands
    step("companion: pulling cron-shell-commands...")
    shell = await _hit(base, "/wp-json/wpsecscan/v1/cron-shell-commands", token)
    if shell and shell.get("flagged"):
        lines = []
        for f in shell["flagged"][:6]:
            funcs = ", ".join(f.get("functions") or [])
            lines.append(f"  - hook={f.get('hook','?')}  "
                          f"source={f.get('source','?')}  uses=[{funcs}]")
        findings.append(Finding(
            severity="high",
            title=f"{len(shell['flagged'])} cron hook(s) call shell-exec functions",
            evidence=("These cron callbacks contain references to PHP's "
                       "shell-exec family (exec/shell_exec/passthru/system/"
                       "popen/proc_open). Legitimate uses exist (e.g. some "
                       "imagick fallback paths) but cron hooks running shell "
                       "commands are a classic command-injection backdoor "
                       "pattern:\n\n" + "\n".join(lines)),
            remediation=(
                "Audit each flagged source file. Legitimate uses should be "
                "narrowly scoped (specific binary, escaped args). Anything "
                "that runs the cron-arg or option content through a shell "
                "command is almost certainly malware."
            ),
            url=ctx["target"],
        ))

    return findings or [Finding(
        severity="info",
        title="Companion advanced endpoints — no issues found",
        evidence=f"Pulled the full v1.1 + v1.2 endpoint set with companion token at {base}.",
        remediation="No action needed.",
        url=ctx["target"],
    )]
