"""wp-cron audit — flag suspicious scheduled callbacks (companion-assisted).

Round-64 #64 — webshells commonly install themselves as a wp-cron job
to maintain persistence even if the original entry-point file is
removed. The companion plugin exposes
/wp-json/wpsecscan-companion/v1/cron-jobs which returns the active
scheduled hooks + their callbacks. We flag callbacks that match
known-bad patterns (eval, base64_decode, system, shell_exec, file_get_
contents from remote URLs, etc.).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Suspicious callback name patterns. Matched as substring (case-sensitive
# for PHP function names which are case-folded by PHP itself).
_SUSPICIOUS_CALLBACKS = (
    "eval", "assert", "base64_decode", "system", "shell_exec",
    "passthru", "exec", "proc_open", "popen", "create_function",
    "file_put_contents", "fwrite", "curl_exec", "fsockopen",
    # Common malware naming patterns
    "wp_cd", "wp_cron_check_", "_____", "x_x", "qqq", "xxx",
)

# Suspicious hook-name patterns (often used by webshells)
_SUSPICIOUS_HOOK_NAMES = (
    "wp_update", "wp_check_", "wp_cron_check", "wpscan", "wpcache",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("querying companion plugin for wp-cron jobs...")
    r = await client.get("/wp-json/wpsecscan-companion/v1/cron-jobs")
    if r is None or r.status_code == 404:
        return findings
    if r.status_code != 200:
        return findings

    try:
        data = r.json()
    except (ValueError, TypeError):
        return findings

    jobs = data.get("jobs", []) if isinstance(data, dict) else []

    suspicious_jobs = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        hook = job.get("hook", "")
        callback = job.get("callback", "")
        # Check both hook and callback strings
        hits = [p for p in _SUSPICIOUS_CALLBACKS if p in str(callback).lower()]
        hits += [p for p in _SUSPICIOUS_HOOK_NAMES if p in str(hook).lower() and hook not in ("wp_update_plugins", "wp_update_themes", "wp_update_themes_check")]
        # De-dupe whitelisted core hooks
        if hook in ("wp_update_plugins", "wp_update_themes", "wp_update_core",
                    "wp_version_check", "wp_scheduled_delete", "wp_privacy_delete_old_export_files"):
            continue
        if hits:
            suspicious_jobs.append({"hook": hook, "callback": callback, "patterns": hits, "next_run": job.get("next_run")})

    if suspicious_jobs:
        for sj in suspicious_jobs:
            findings.append(
                Finding(
                    severity="critical",
                    title=f"Suspicious wp-cron job: {sj['hook']}",
                    evidence=f"Hook: {sj['hook']!r}\n  Callback: {sj['callback']!r}\n  Matched: {', '.join(sj['patterns'])}\n  Next run: {sj['next_run']}",
                    remediation=(
                        "This wp-cron job is likely persistence for a webshell. Steps:\n"
                        "  1. From wp-cli: `wp cron event delete <hook-name>`\n"
                        "  2. Find + remove the PHP file registering the hook (grep 'wp_schedule_event' your code).\n"
                        "  3. Audit other persistence (DB triggers, mu-plugins, .htaccess auto_prepend_file).\n"
                        "  4. Rotate admin credentials + WP salts.\n"
                        "  5. Restore from a known-clean backup if compromise is confirmed."
                    ),
                    url=client.url("/wp-cron.php"),
                    extra=sj,
                )
            )
    elif jobs:
        findings.append(
            Finding(
                severity="info",
                title=f"{len(jobs)} wp-cron jobs scheduled — none matched malicious patterns",
                evidence=f"Checked {len(jobs)} hook(s); review periodically.",
                remediation="If site is on a host without real cron, switch DISABLE_WP_CRON=true + system cron for reliability.",
                url=client.url("/wp-json/wpsecscan-companion/v1/cron-jobs"),
            )
        )

    return findings
