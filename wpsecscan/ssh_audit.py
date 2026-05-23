"""SSH wp-cli audit — connects to a user-controlled host via the system
ssh client and runs a hard-coded list of read-only `wp` commands.

Usage:
  wpsecscan --ssh-audit user@host

The command list is a constant tuple. Each entry is a plain list of args
passed to subprocess.run([...]); we never use shell=True or build commands
from string interpolation.
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone

from . import db as vulndb
from .models import CheckResult, Finding, ScanReport

# Hard-coded ssh args. We never interpolate user data into the command list
# beyond the user@host argument, which is validated as a single token before
# we get here.
WP_COMMANDS: tuple[tuple[str, list[str]], ...] = (
    ("core_version",        ["wp", "core", "version"]),
    ("plugins",             ["wp", "plugin", "list", "--format=json"]),
    ("themes",              ["wp", "theme", "list", "--format=json"]),
    ("admins",              ["wp", "user", "list", "--role=administrator", "--format=json"]),
    ("siteurl",             ["wp", "option", "get", "siteurl"]),
    ("home",                ["wp", "option", "get", "home"]),
    ("default_role",        ["wp", "option", "get", "default_role"]),
    ("users_can_register",  ["wp", "option", "get", "users_can_register"]),
)


def _validate_ssh_target(target: str) -> str:
    """Reject anything that looks like shell injection or ssh option injection."""
    target = target.strip()
    if not target:
        raise ValueError("empty ssh target")
    # Defense against ssh argument injection — targets starting with - would be
    # interpreted as options (e.g. "-oProxyCommand=evil" routes the connection
    # through an attacker-controlled command).
    if target.startswith("-"):
        raise ValueError(f"ssh target may not start with '-': {target!r}")
    # Defense against shell metacharacters — none of these can appear in a
    # legitimate user@host string.
    forbidden = (" ", "\t", "\n", ";", "|", "&", "$", "`", "<", ">", "(", ")", "{", "}", '"', "'")
    if any(c in target for c in forbidden):
        raise ValueError(f"ssh target contains forbidden characters: {target!r}")
    return target


def _ssh_run(target: str, cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    """Returns (returncode, stdout, stderr). Never raises.
    Note: ssh's `--` separator forces the next arg to be the destination, not an option."""
    full = (
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=accept-new", "--", target]
        + cmd
    )
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        return -2, "", "ssh client not found in PATH"
    except OSError as e:
        return -3, "", f"OSError: {e}"


def audit(target: str) -> ScanReport:
    """Run the ssh audit and return a ScanReport-shaped result."""
    target = _validate_ssh_target(target)
    started = time.perf_counter()
    started_wall = datetime.now(timezone.utc).isoformat()

    # 1. Verify ssh + wp-cli are usable
    rc, out, err = _ssh_run(target, ["wp", "--version"], timeout=15)
    if rc != 0:
        return ScanReport(
            target=f"ssh://{target}",
            scanned_at=started_wall,
            duration_ms=int((time.perf_counter() - started) * 1000),
            results=[CheckResult(
                check_id="ssh_connect",
                check_name="SSH connection / wp-cli",
                findings=[Finding(
                    severity="medium",
                    title=f"SSH or wp-cli not usable on {target}",
                    evidence=(
                        f"`ssh {target} wp --version` returned exit {rc}\n"
                        f"stdout: {out[:300]}\nstderr: {err[:500]}"
                    ),
                    remediation=(
                        "Verify ssh keys are configured (BatchMode=yes is required — no password prompts). "
                        "Install wp-cli on the remote host: https://wp-cli.org/#installing — "
                        "or specify the WP install path with `wp --path=/var/www/html ...` (this scanner uses the default path)."
                    ),
                    url=f"ssh://{target}",
                )],
            )],
        )

    findings_by_check: dict[str, list[Finding]] = {}

    # 2. Core version vs latest
    rc, out, err = _ssh_run(target, ["wp", "core", "version"])
    core_ver = out.strip() if rc == 0 else None
    if core_ver:
        findings_by_check.setdefault("core_version", []).append(Finding(
            severity="info",
            title=f"WordPress core: {core_ver}",
            evidence=f"`wp core version` -> {core_ver}",
            remediation="Cross-reference against latest from api.wordpress.org and update if needed.",
            url=f"ssh://{target}",
        ))

    # 3. Plugins
    rc, out, err = _ssh_run(target, ["wp", "plugin", "list", "--format=json"])
    plugins_list: list[dict] = []
    if rc == 0:
        try:
            plugins_list = json.loads(out)
        except json.JSONDecodeError:
            pass
    if plugins_list:
        active = sum(1 for p in plugins_list if p.get("status") == "active")
        inactive = sum(1 for p in plugins_list if p.get("status") == "inactive")
        findings_by_check.setdefault("plugins", []).append(Finding(
            severity="info",
            title=f"Definitive plugin list: {active} active, {inactive} inactive ({len(plugins_list)} total)",
            evidence="\n".join(
                f"  - {p.get('name','?')} {p.get('version','?')} [{p.get('status','?')}]"
                for p in plugins_list[:30]
            ),
            remediation="Delete inactive plugins — they still receive PHP execution if a CVE drops while installed.",
            url=f"ssh://{target}",
        ))
        # Cross-reference each plugin against the vuln DB
        vulns, _, _ = vulndb.load_local()
        for p in plugins_list:
            slug = p.get("name")
            ver = p.get("version")
            if not slug or not ver:
                continue
            matches = vulndb.find_for(vulns, "plugin", slug, ver)
            for v in matches:
                findings_by_check.setdefault("plugin_cves", []).append(Finding(
                    severity=v.severity,
                    title=f"Known vulnerability in {slug} {ver}: {v.title[:120]}",
                    evidence=(
                        f"Detected via authenticated wp-cli on {target}.\n"
                        f"  Plugin: {slug}\n  Installed: {ver}\n"
                        + (f"  Fixed in: {v.fixed_in}\n" if v.fixed_in else "")
                        + (f"  CVE: {v.cve}\n" if v.cve else "")
                    ),
                    remediation=f"Run on the box: `ssh {target} wp plugin update {slug}` (or to {v.fixed_in} specifically).",
                    url=f"ssh://{target}",
                    extra={"cve": v.cve, "fixed_in": v.fixed_in, "cvss": v.cvss},
                ))

    # 4. Admin accounts
    rc, out, err = _ssh_run(target, ["wp", "user", "list", "--role=administrator", "--format=json"])
    if rc == 0:
        try:
            admins = json.loads(out)
            if isinstance(admins, list):
                lines = "\n".join(f"  - {a.get('user_login','?')}  <{a.get('user_email','?')}>" for a in admins)
                sev = "medium" if len(admins) > 2 else "info"
                findings_by_check.setdefault("admins", []).append(Finding(
                    severity=sev,
                    title=f"{len(admins)} administrator account(s)",
                    evidence=f"`wp user list --role=administrator`:\n{lines}",
                    remediation=(
                        "Audit every admin. Demote anyone who doesn't strictly need it. "
                        "Force 2FA on all remaining admins. Watch for accounts you didn't create."
                    ),
                    url=f"ssh://{target}",
                ))
        except json.JSONDecodeError:
            pass

    # 5. Option flags
    options: dict[str, str] = {}
    for opt in ("siteurl", "home", "default_role", "users_can_register"):
        rc, out, err = _ssh_run(target, ["wp", "option", "get", opt])
        if rc == 0:
            options[opt] = out.strip()
    if options:
        problems: list[str] = []
        if options.get("default_role", "").lower() == "administrator":
            problems.append("default_role = administrator (NEW REGISTRATIONS BECOME ADMINS)")
        if options.get("users_can_register") == "1" and options.get("default_role", "").lower() in ("administrator", "editor"):
            problems.append(f"users_can_register=ON + default_role={options['default_role']} (high-priv self-registration)")
        sev = "high" if problems else "info"
        findings_by_check.setdefault("options", []).append(Finding(
            severity=sev,
            title=("Dangerous WP options" if problems else "WP options look OK"),
            evidence=(
                "\n".join(f"  {k} = {v}" for k, v in options.items())
                + (("\n\nProblems:\n" + "\n".join(f"  ! {p}" for p in problems)) if problems else "")
            ),
            remediation=(
                "Set default_role to 'subscriber' or 'contributor'. Disable user registration unless you actually need it."
                if problems else "No action needed."
            ),
            url=f"ssh://{target}",
        ))

    # Build CheckResults
    check_meta = {
        "ssh_connect":   "SSH connection / wp-cli",
        "core_version":  "WordPress core version (via wp-cli)",
        "plugins":       "Plugins (via wp-cli)",
        "plugin_cves":   "Plugin CVE matching (via wp-cli)",
        "admins":        "Administrator accounts (via wp-cli)",
        "options":       "WP options audit (via wp-cli)",
    }
    results: list[CheckResult] = []
    for cid in ("ssh_connect", "core_version", "plugins", "plugin_cves", "admins", "options"):
        if cid in findings_by_check:
            results.append(CheckResult(check_id=cid, check_name=check_meta[cid], findings=findings_by_check[cid]))

    return ScanReport(
        target=f"ssh://{target}",
        scanned_at=started_wall,
        duration_ms=int((time.perf_counter() - started) * 1000),
        results=results,
    )
