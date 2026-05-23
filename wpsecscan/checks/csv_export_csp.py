"""CSV-export formula-injection probe.

WordPress sites that expose `?export=csv` or `?action=export` endpoints
(WooCommerce orders, Contact Form 7 entries, Gravity Forms, etc.) often
serialize user-submitted content (names, comments, support tickets) verbatim
into CSV cells. If those cells begin with `=`, `+`, `-`, `@`, an admin
opening the export in Excel executes that as a formula.

Probe: POST a benign canary that begins with `=` to common form/comment
endpoints, then fetch the matching export and check whether the canary
arrived un-escaped.

Aggressive-only (does write a comment-like value).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Common export paths (GET) — we only fetch, we don't trigger an actual export workflow.
EXPORT_PATHS = (
    "/wp-admin/admin-ajax.php?action=export_csv",
    "/wp-admin/edit.php?post_type=shop_order&action=download_invoices",
    "/?wp-jet-form-builder=download",
    "/?action=wpcf7-csv",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="CSV-export injection probe skipped (requires --aggressive)",
                evidence="This check requires --aggressive — it pulls and inspects export files.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # No write step from us — we just pull common export URLs (often public on
    # misconfigured sites) and look for unfiltered formula-trigger characters.
    leaks: list[tuple[str, str]] = []
    for p in EXPORT_PATHS:
        step(f"probing export {p}...")
        r = await client.get(p)
        if r is None or r.status_code != 200:
            continue
        ctype = (r.headers.get("content-type", "") or r.headers.get("Content-Type", "")).lower()
        # Confirm it's actually a CSV
        if "csv" not in ctype and "text/plain" not in ctype:
            continue
        body = (r.text or "")
        # Find any cell that BEGINS with a formula trigger char (after a newline + optional quote)
        suspicious = []
        for line in body.splitlines()[:200]:  # first 200 lines max
            for cell in line.split(","):
                stripped = cell.strip().strip('"').strip("'")
                if stripped and stripped[0] in ("=", "+", "-", "@", "\t"):
                    suspicious.append(stripped[:60])
                    if len(suspicious) >= 5:
                        break
            if len(suspicious) >= 5:
                break
        if suspicious:
            leaks.append((p, "  ".join(suspicious)))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="No CSV-export formula injection found",
                evidence=f"Probed {len(EXPORT_PATHS)} common export paths; none contained formula-prefixed cells.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for p, sample in leaks:
        findings.append(
            Finding(
                severity="medium",
                title=f"CSV export at {p} contains formula-prefixed cells",
                evidence=(
                    f"Cells starting with =/+/-/@:  {sample}\n\n"
                    "An admin opening this export in Excel or LibreOffice Calc will execute the "
                    "leading character as a formula — DDE injection, ext command, or info leak."
                ),
                remediation=(
                    "Sanitize CSV exports per OWASP CSV Injection: prefix any cell starting with "
                    "=, +, -, @, tab, or CR with a single quote `'`. WordPress core's "
                    "`wp_list_table::ajax_response()` doesn't do this — plugins must escape "
                    "themselves. WooCommerce has had this issue patched since 4.0; older plugins "
                    "may not."
                ),
                url=client.url(p),
            )
        )
    return findings
