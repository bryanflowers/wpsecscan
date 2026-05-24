"""Deep .git directory enumeration.

Round-64 #66 — existing git_exposure.py flags an exposed .git/config.
This deep variant tries to actually walk .git/HEAD → .git/refs/heads/* →
.git/objects/* to estimate how much of the repo an attacker could
reconstruct. Even partial reconstruction often leaks credentials.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("checking .git/HEAD...")
    r = await client.get("/.git/HEAD")
    if r is None or r.status_code != 200:
        return findings  # nothing to do
    head_text = (r.text or "").strip()
    if not head_text.startswith("ref:") and not re.match(r"^[0-9a-f]{40}$", head_text):
        return findings  # not a valid git HEAD

    findings.append(
        Finding(
            severity="critical",
            title=".git/HEAD readable — likely full repo reconstructible",
            evidence=f"GET /.git/HEAD -> 200\n  Contents: {head_text!r}",
            remediation=(
                "Block /.git/* publicly:\n"
                "  Apache:  RedirectMatch 404 /\\.git\n"
                "  Nginx:   location ~ /\\.git { deny all; return 404; }\n"
                "Then audit the repo for committed secrets (gitleaks, trufflehog) — assume an attacker has them."
            ),
            url=client.url("/.git/HEAD"),
        )
    )

    step("checking .git/config (read-only)...")
    r2 = await client.get("/.git/config")
    if r2 is not None and r2.status_code == 200 and "[core]" in (r2.text or ""):
        cfg = r2.text or ""
        # Look for remote URLs that include credentials inline
        m = re.search(r'url\s*=\s*https?://[^:/\s]+:[^@\s]+@[^\s]+', cfg)
        if m:
            findings.append(
                Finding(
                    severity="critical",
                    title="Credentials embedded in .git/config remote URL",
                    evidence=f"Found: {m.group(0)[:80]}...",
                    remediation="ROTATE the credentials immediately. Block /.git/* publicly.",
                    url=client.url("/.git/config"),
                )
            )

    step("checking .git/refs/heads...")
    r3 = await client.get("/.git/refs/heads/main")
    if r3 is None or r3.status_code != 200:
        r3 = await client.get("/.git/refs/heads/master")
    if r3 is not None and r3.status_code == 200:
        ref_text = (r3.text or "").strip()
        if re.match(r"^[0-9a-f]{40}$", ref_text):
            findings.append(
                Finding(
                    severity="critical",
                    title="Branch refs reachable — `git-dumper` style reconstruction possible",
                    evidence=f"Got commit SHA from refs/heads: {ref_text}",
                    remediation="Any object reachable from this SHA can be reconstructed by an attacker. See https://github.com/arthaud/git-dumper.",
                    url=client.url("/.git/refs/heads/"),
                )
            )

    step("checking .git/index (binary, but useful)...")
    r4 = await client.get("/.git/index")
    if r4 is not None and r4.status_code == 200 and len(r4.content or b"") > 0:
        magic = (r4.content or b"")[:4]
        if magic == b"DIRC":
            findings.append(
                Finding(
                    severity="critical",
                    title=".git/index readable — full filename inventory leaked",
                    evidence=f"GET /.git/index -> 200, {len(r4.content)} bytes, DIRC magic confirmed",
                    remediation="An attacker can enumerate every file in the repo from .git/index. Block /.git/* publicly NOW.",
                    url=client.url("/.git/index"),
                )
            )

    return findings
