"""#10-15 — Plugin-specific deep audits in one module.

#10 Gravity Forms file-upload MIME-confusion probe (aggressive)
#11 ACF Pro license JWT leak scan
#12 Multisite tenant-isolation probe
#13 ManageWP / MainWP / iThemes Sync agent detection
#14 Child-theme override fingerprint
#15 WP-CLI exposure (`/wp-cli.phar`, command-passthrough hacks)
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


ACF_JWT_RE = re.compile(r"acf[_-]?pro[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9-_]{30,})", re.IGNORECASE)
MULTISITE_INDICATOR = ("wp-signup.php", "is_multisite", "ms-files.php")
AGENT_PATHS = (
    ("/wp-content/plugins/worker/init.php",    "ManageWP / MainWP worker plugin"),
    ("/wp-content/plugins/mainwp-child/index.php", "MainWP child"),
    ("/wp-content/plugins/sync/index.php",     "iThemes Sync"),
    ("/wp-content/plugins/wp-remote-manager/index.php", "WP Remote"),
    ("/wp-content/plugins/jetpack/jetpack.php", "Jetpack"),  # not malicious but big attack surface
)
WP_CLI_PATHS = ("/wp-cli.phar", "/wp", "/?wp_cli=run", "/?cli=info")
CHILD_THEME_RE = re.compile(r'/wp-content/themes/([^/"\'\s]+)/style\.css', re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    home = await client.get("/")
    body = (home.text or "")[:100_000] if home else ""

    # #11 ACF JWT leak
    for m in ACF_JWT_RE.finditer(body):
        findings.append(Finding(
            severity="critical",
            title="ACF Pro license JWT leaked in front-end HTML",
            evidence=f"Matched pattern: {m.group(1)[:8]}...{m.group(1)[-4:]}",
            remediation="Rotate the ACF Pro license at https://www.advancedcustomfields.com/my-account/. Audit the plugin/theme that's calling wp_localize_script() with the license value — never expose it on the public side.",
            url=ctx["target"],
        ))

    # #12 Multisite indicator + cross-tenant isolation probe (minimal)
    if any(ind in body for ind in MULTISITE_INDICATOR):
        step("multisite: probing tenant isolation...")
        # On a multisite install, /wp-admin/network/ is reachable; sub-blogs at /site-1/, /site-2/, etc.
        # We do a single check: hit /wp-json/wp/v2/users?per_page=100 and look for users from multiple blogs
        r = await client.get("/wp-json/wp/v2/users?per_page=100")
        if r is not None and r.status_code == 200:
            try:
                users = r.json() or []
                blog_ids = {u.get("meta", {}).get("blog_id") for u in users if isinstance(u, dict)}
                blog_ids.discard(None)
                if len(blog_ids) > 1:
                    findings.append(Finding(
                        severity="medium",
                        title=f"Multisite REST: users from {len(blog_ids)} blogs returned in one call",
                        evidence=f"GET /wp-json/wp/v2/users returned users with blog_ids {sorted(blog_ids)} — cross-tenant info leak.",
                        remediation="Filter REST users by current blog OR require admin. The `pre_get_users` filter can scope `blog_id = get_current_blog_id()`.",
                        url=ctx["target"] + "/wp-json/wp/v2/users",
                    ))
            except Exception:  # noqa: BLE001
                pass

    # #13 Agent detection
    for path, label in AGENT_PATHS:
        step(f"agent probe {label}...")
        r = await client.head(path)
        if r is None or r.status_code != 200:
            continue
        findings.append(Finding(
            severity="low",
            title=f"Remote-management agent detected: {label}",
            evidence=f"{path} responds 200 OK.",
            remediation=f"Confirm the agent is intentional. If you're not using {label}, deactivate + delete the plugin (attack surface — these tools have had RCEs historically).",
            url=ctx["target"] + path,
        ))

    # #14 Child-theme detection (if both child and parent themes load)
    themes_in_html = set(CHILD_THEME_RE.findall(body))
    if len(themes_in_html) > 1:
        findings.append(Finding(
            severity="info",
            title=f"Child theme detected: {', '.join(sorted(themes_in_html))}",
            evidence=f"Multiple theme directories serve assets — likely a parent + child setup.",
            remediation="Audit the child theme's `functions.php` for security hardening that might be overriding parent-theme defaults (e.g., removing nonce checks, or echoing user input without escape).",
            url=ctx["target"],
        ))

    # #15 WP-CLI exposure
    for p in WP_CLI_PATHS:
        r = await client.head(p)
        if r is not None and r.status_code == 200:
            findings.append(Finding(
                severity="critical",
                title=f"WP-CLI artifact accessible: {p}",
                evidence=f"{p} returned 200. wp-cli.phar in the web root is a full RCE waiting to happen if PHP exec is on.",
                remediation=f"Delete {p}. wp-cli should NEVER live in the web root. Install via `composer global require wp-cli/wp-cli` instead, and keep it outside the doc root.",
                url=ctx["target"] + p,
            ))

    if not findings:
        return [Finding(severity="info", title="Plugin-specific deep audit — clean",
                        evidence="No ACF/MS/agent/child/WP-CLI red flags.",
                        remediation="No action.", url=ctx["target"])]
    return findings


async def gravity_forms_upload_bypass(client: Client, ctx: dict) -> list[Finding]:
    """#10 standalone — only fired by aggressive mode + when GF is detected."""
    # Placeholder for the full polyglot upload test; emits an info finding for now.
    return [Finding(
        severity="info",
        title="Gravity Forms upload-bypass probe — manual follow-up",
        evidence="Automated GF upload-bypass requires a CSRF-fresh form session + valid nonce. Use Burp Suite's `Intruder` against the form's `upload_file_X` field.",
        remediation="Set GF's file-type allow-list explicitly (no `*` wildcards). Add `disable_php_execution` in the upload directory's nginx config.",
        url=ctx["target"],
    )]
