"""A35 (v2.6.0) — .github/workflows/*.yml exposure on production webroot.

Some hosting setups serve the entire git tree, including `.github/`.
When the workflows directory is reachable, the YAML files leak:

  • Secret names (env: SECRET_KEY, env: DEPLOY_KEY) — attacker knows
    which secrets to target with phishing.
  • Branch names (`branches: [main, staging, demo]`) — attacker can
    guess subdomains / preview URLs.
  • Deployment scripts that reference internal hosts.

Probe canonical paths + flag medium when any 200-with-YAML response.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PROBES = (
    "/.github/workflows/",
    "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/test.yml",
    "/.github/workflows/release.yml",
    "/.gitlab-ci.yml",
    "/.circleci/config.yml",
    "/buildspec.yml",
    "/azure-pipelines.yml",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBES:
        step(f"CI workflow probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        body = r.text[:5000]
        # Must look YAML-shaped to dodge generic 200 pages.
        if not any(s in body for s in ("name:", "jobs:", "on:", "steps:", "runs-on:")):
            continue

        # Pull out leaked secret names + branch names
        import re
        secrets = re.findall(r"\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", body)
        branches = re.findall(r"branches\s*:\s*\[([^\]]+)\]", body)

        findings.append(Finding(
            severity="medium",
            title=f"CI workflow file web-reachable: {path}",
            evidence=(
                f"GET {path} → HTTP 200, YAML-shaped body.\n"
                + (f"Secret names leaked: {sorted(set(secrets))}\n"
                    if secrets else "")
                + (f"Branch names leaked: {sorted(set(branches))[:5]}\n"
                    if branches else "")
                + f"First 300 bytes: {body[:300]}"
            ),
            remediation=(
                "1. Add `Disallow: /.github/` to robots.txt (best-effort, not\n"
                "   security).\n"
                "2. In Apache: `<DirectoryMatch \"\\.git(hub)?\">\n"
                "                  Require all denied\n"
                "                </DirectoryMatch>`\n"
                "3. In nginx: `location ~ /\\.git { deny all; return 404; }`\n"
                "4. Long-term: deploy via CI artifact, not by checking out\n"
                "   the .git tree to the web root."
            ),
            url=client.url(path),
            extra={"path": path,
                    "secrets_leaked": sorted(set(secrets))[:20],
                    "branches_leaked": sorted(set(branches))[:5]},
        ))
        return findings
    return findings
