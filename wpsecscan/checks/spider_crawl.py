"""#18 — spider check: runs the crawler + reports the URL inventory.

Reports the number of URLs discovered, depth-of-deepest-page, and any
robots.txt-blocked paths. Stashes the URL list in ctx['shared']['urls']
so later checks can consume it.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    from .. import spider as _sp
    step("spider: crawling target...")
    result = await _sp.crawl(client, max_depth=3, max_pages=200)

    if not result.urls:
        findings.append(Finding(
            severity="info",
            title="Spider — no URLs crawled",
            evidence="Couldn't fetch / or no internal links were found.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    shared = ctx.setdefault("shared", {})
    shared["urls"] = result.urls
    deepest = max(result.depth_of.values(), default=0)

    findings.append(Finding(
        severity="info",
        title=f"Spider crawled {len(result.urls)} URL(s) (max depth {deepest})",
        evidence=(
            f"First 20 discovered URLs:\n  " + "\n  ".join(result.urls[:20])
            + (f"\n... and {len(result.urls) - 20} more" if len(result.urls) > 20 else "")
            + (f"\n\n{len(result.blocked_by_robots)} URL(s) skipped due to robots.txt Disallow."
               if result.blocked_by_robots else "")
            + (f"\n{result.errors} fetch error(s)." if result.errors else "")
            + "\n\nDownstream checks can now probe these URLs instead of just the homepage."
        ),
        remediation="No action — informational. Use --no-spider if you want only the "
                    "hard-coded path list (faster but less coverage).",
        url=ctx["target"],
    ))
    return findings
