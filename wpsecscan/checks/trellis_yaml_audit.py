"""N137 (v2.7.0) — Roots Trellis YAML anti-pattern audit.

When the existing host_platform_detect check fingerprints a Bedrock or
Roots stack, this companion probes for Trellis-specific config
exposure: group_vars/ + ansible.cfg are sometimes deployed to the
web root in mis-configured installs, leaking SSH usernames, vault
passwords, and host inventories.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PATHS = (
    "/group_vars/all/vault.yml",
    "/group_vars/development/main.yml",
    "/group_vars/production/main.yml",
    "/ansible.cfg",
    "/site.yml",
    "/dev.yml",
    "/server.yml",
    "/trellis/group_vars/all/vault.yml",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    home = await client.get("/")
    body = (home.text or "").lower() if home else ""
    is_roots = any(s in body for s in ("/app/themes/", "/app/uploads/", "bedrock"))

    for path in _PATHS:
        step(f"Trellis probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        looks_yaml = any(s in r.text for s in ("vault_", "wp_env:", "site_hosts:",
                                                  "wordpress_sites:", "[defaults]"))
        if not looks_yaml:
            continue
        findings.append(Finding(
            severity="critical",
            title=f"Trellis / Ansible config web-reachable: {path}",
            evidence=(
                f"GET {path} → HTTP 200, YAML-shaped body.\n"
                f"Excerpt: {r.text[:300]}\n"
                "Trellis config typically contains SSH usernames, hostnames, "
                "and vault-encrypted secrets. Anyone on the internet can "
                "read it."
            ),
            remediation=(
                "1. IMMEDIATE: block /group_vars/, /ansible.cfg, /site.yml at the WAF.\n"
                "2. Move the Trellis tree OUT of the web root — Trellis expects to\n"
                "   live at /srv/www/<site>/current/web/ with the YAML files above\n"
                "   that path.\n"
                "3. Rotate any vault-stored secret that was reachable."
            ),
            url=client.url(path),
            extra={"path": path, "category": "trellis-exposure"},
        ))
    return findings
