"""L29 Custom-check scaffold generator.

Generates a starter Python file the user can drop into ~/.wpsecscan/plugins/.
A Lua/JS sandbox was descoped — Python plugins are already supported and
have the full asyncio+httpx stack available, so the gap is just discoverability.

The generated file:
  - Has the correct module-level constants (CHECK_ID, CHECK_NAME, IS_AGGRESSIVE)
  - Implements `async def check(client, ctx) -> list[Finding]:`
  - Includes 3 worked examples in comments (passive GET, JSON-body check, regex sink)
"""
from __future__ import annotations

from pathlib import Path

SCAFFOLD = '''"""Custom WPSecScan check — drop this file in ~/.wpsecscan/plugins/.

Auto-discovered at scanner startup (or via Tools -> Reload custom checks in the GUI).

The contract:
  CHECK_ID:      str  (required, unique across all checks — built-ins cannot be shadowed)
  CHECK_NAME:    str  (required, human display name)
  IS_AGGRESSIVE: bool (default False; if True, gated behind --aggressive)
  async def check(client, ctx) -> list[Finding]
    - client: wpsecscan.http.Client (or compatible fake in tests)
        .get(path, **kwargs), .post(...), .head(...), .request(method, ...)
        .url(path) -> absolute URL
    - ctx: dict with at least:
        "target":     base URL
        "shared":     dict for cross-check state (e.g. ctx["shared"]["plugins"])
        "step":       callable(str) for progress reporting (optional)
        "aggressive": bool

Every Finding must use one of: info | low | medium | high | critical.
"""
from __future__ import annotations

from wpsecscan.models import Finding


CHECK_ID = "my_custom_check"
CHECK_NAME = "My custom check"
IS_AGGRESSIVE = False


async def check(client, ctx) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # --- Example 1: passive GET ---
    step("checking /robots.txt for a custom marker...")
    r = await client.get("/robots.txt")
    if r is not None and "MY_BAD_MARKER" in (r.text or ""):
        findings.append(Finding(
            severity="medium",
            title="Custom marker leaked in robots.txt",
            evidence="`MY_BAD_MARKER` is present in /robots.txt — was probably committed by mistake.",
            remediation="Remove the marker from your published robots.txt.",
            url=ctx["target"] + "/robots.txt",
        ))

    # --- Example 2: JSON body check ---
    # step("checking REST endpoint for over-disclosed fields...")
    # r = await client.get("/wp-json/wp/v2/users/me")
    # if r is not None and r.status_code == 200:
    #     try:
    #         data = r.json()
    #     except Exception:
    #         data = {}
    #     if "email" in data:
    #         findings.append(Finding(
    #             severity="high",
    #             title="User /me endpoint discloses email to unauth",
    #             evidence=f"Body contained `email`: {data['email']}",
    #             remediation="Restrict the /me endpoint to authenticated requests.",
    #             url=client.url("/wp-json/wp/v2/users/me"),
    #         ))

    # --- Example 3: regex sink scan ---
    # import re
    # PATTERN = re.compile(r"my-internal-tool-version:\\s*([\\d.]+)")
    # r = await client.get("/")
    # if r is not None:
    #     m = PATTERN.search(r.text or "")
    #     if m:
    #         version = m.group(1)
    #         findings.append(Finding(
    #             severity="low",
    #             title=f"Internal tool version disclosed: {version}",
    #             evidence=f"Found in homepage HTML.",
    #             remediation="Strip the version header in production.",
    #             url=ctx["target"],
    #         ))

    return findings
'''


def scaffold_path() -> Path:
    """Default scaffold output: ~/.wpsecscan/plugins/example_check.py"""
    from . import history as _h
    return Path(_h._home()) / "plugins" / "example_check.py"


def write_scaffold(*, path: Path | None = None, overwrite: bool = False) -> Path:
    """Write the scaffold file to disk. Returns the path written.

    By default refuses to overwrite an existing file; pass overwrite=True to force.
    """
    if path is None:
        path = scaffold_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {path} (pass overwrite=True)")
    path.write_text(SCAFFOLD, encoding="utf-8")
    return path
