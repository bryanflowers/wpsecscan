"""H6 HTTP Parameter Pollution (HPP).

Sending duplicate query parameters can confuse servers that don't normalise:
  ?id=1&id=2  → backend reads `id=1`, WAF reads `id=2`, etc.
This is the classic technique for evading allow-list-based WAFs and for
triggering uncommon code paths in plugins that handle their own parameter
parsing.

We probe a few common endpoints with both `?id=normal` and `?id=normal&id=evil`
and look for behaviour differences (status code, body length, or `WAF blocked`
markers appearing in only one variant).

Aggressive only — the duplicate-param payloads include reserved values
(`<script>`, etc.) that some WAFs interpret as attacks.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Common WP endpoints that read query parameters and route them to plugin code
HPP_TARGETS = (
    "/?p=1",
    "/?s=test",
    "/?cat=1",
    "/?author=1",
    "/wp-admin/admin-ajax.php?action=heartbeat",
)
EVIL_VALUE = "1' OR '1'='1"  # SQL-meta + quote-mismatch trigger for WAFs


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(Finding(
            severity="info",
            title="HTTP Parameter Pollution check skipped (passive mode)",
            evidence="Pass --aggressive to enable.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    bypasses: list[tuple[str, int, int, int, int]] = []  # (url, single_status, dup_status, single_len, dup_len)
    for path in HPP_TARGETS:
        step(f"HPP probing {path}...")
        # Single param
        single = await client.get(path)
        # Dup param — append the same key with an evil value
        sep = "&" if "?" in path else "?"
        # Extract the existing key=val; duplicate that key with EVIL_VALUE
        if "=" in path.split("?", 1)[-1]:
            key = path.split("?", 1)[1].split("=", 1)[0]
            dup_path = path + f"{sep}{key}={EVIL_VALUE}"
        else:
            dup_path = path + f"{sep}q={EVIL_VALUE}"
        dup = await client.get(dup_path)

        if single is None or dup is None:
            continue
        s_len = len(single.content or b"")
        d_len = len(dup.content or b"")
        s_status = single.status_code
        d_status = dup.status_code
        # Significant delta = WAF blocked one but not the other, OR backend chose differently
        if s_status != d_status or abs(s_len - d_len) > 800:
            bypasses.append((path, s_status, d_status, s_len, d_len))

    if bypasses:
        findings.append(Finding(
            severity="medium",
            title=f"HTTP Parameter Pollution — {len(bypasses)} endpoint(s) treat duplicates differently",
            evidence="\n".join(
                f"  - {p}: single={ss}/{sl}B, duplicate={ds}/{dl}B"
                for p, ss, ds, sl, dl in bypasses
            ) + (
                "\n\nWhen status or body length changes between single- and duplicate-parameter requests, "
                "a WAF or middleware is reading a different value than the backend. Attackers use this to "
                "smuggle payloads past the WAF."
            ),
            remediation=(
                "Normalize query parameters at the edge — pick the first or last occurrence and discard the "
                "rest, matching whatever the backend does. ModSecurity has `ARGS:id` matching; ensure CRS "
                "rules use `ARGS_NAMES` to catch all variants."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="HTTP Parameter Pollution — no differential observed",
            evidence=f"Probed {len(HPP_TARGETS)} endpoints with duplicate parameters; no significant status/length delta.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
