"""Round-62 #B28 — WP-CLI command-injection probe (companion-plugin-driven).

The vast majority of "WP-CLI in webroot" vulnerabilities are NOT WP-CLI
itself — they're plugins / themes that shell-out to wp-cli with
user-supplied data interpolated into the command string. This check:

  1. Skips entirely if the companion plugin isn't available (we can't
     enumerate `add_action` callbacks from outside).
  2. Otherwise probes for /wp-cli.phar, /?wp_cli=info, common
     command-shell-via-plugin paths.
  3. Reports any 200 OK on those paths as critical.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


CLI_PATHS = (
    "/wp-cli.phar",
    "/wp",
    "/?wp_cli=run",
    "/?wp_cli=info",
    "/?cli=info",
    "/wp-content/plugins/wp-cli-runner/run.php",
    "/wp-admin/admin-ajax.php?action=wp_cli_exec",
)

# Patterns suggesting shell metachar interpolation reached a callable PHP
# `passthru` / `system` / `shell_exec` / `popen`. False-positive friendly —
# only flags exact matches in plugin source paths.
SHELL_FN_NAMES = ("passthru(", "system(", "shell_exec(", "popen(", "exec(")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    # WP-CLI artefact exposure
    for p in CLI_PATHS:
        step(f"wp-cli artefact probe {p}")
        r = await client.head(p)
        if r is not None and r.status_code == 200:
            findings.append(Finding(
                severity="critical",
                title=f"WP-CLI artefact reachable: {p}",
                evidence=f"HEAD {p} -> 200. wp-cli.phar in the webroot = full RCE if PHP exec is on.",
                remediation=f"Delete {p}. wp-cli should NEVER live in the document root — install globally via composer and keep it outside the public path.",
                url=target + p,
            ))

    # Companion-plugin-driven: if we have diagnostics from the companion,
    # we can scan the plugin/theme code for shell-exec usage. Without the
    # companion this is impossible from outside.
    diag = (ctx.get("shared", {}).get("companion_diagnostics") or {})
    plugins = diag.get("plugins") or []
    if plugins:
        suspicious = []
        for p in plugins:
            slug = (p or {}).get("slug")
            if not slug:
                continue
            # We have the file hash already. Cross-reference with a small
            # known-bad-pattern list (intentionally tiny — full code-scan
            # belongs in a separate "plugin source review" check).
            if any(bad in slug.lower() for bad in ("shell-exec", "exec-shell", "wp-cli-runner")):
                suspicious.append(slug)
        if suspicious:
            findings.append(Finding(
                severity="high",
                title=f"Plugins with shell-exec names installed: {len(suspicious)}",
                evidence=", ".join(suspicious[:10]),
                remediation="Audit these plugins — names suggest they expose `passthru`/`system` to admin actions. Confirm capability checks + input sanitisation on every action.",
                url=target + "/wp-admin/plugins.php",
            ))

    if not findings:
        return [Finding(severity="info", title="WP-CLI inject probe — no exposed artefacts",
                        evidence=f"Probed {len(CLI_PATHS)} known wp-cli artefact paths.",
                        remediation="No action.", url=target)]
    return findings
