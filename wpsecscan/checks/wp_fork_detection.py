"""Item #19 — WordPress fork detection (ClassicPress, Bedrock layout, Roots, etc.).

Some checks assume vanilla WP file layout / REST behaviour and produce false
positives on a fork:
  - ClassicPress (no Gutenberg; v1.x is still a thing; reports as
    "ClassicPress" in the REST API generator field).
  - Bedrock (Roots) — `wp-config.php` lives in /config/, plugins live in
    `/app/plugins/`, themes in `/app/themes/`. Checks that probe
    `/wp-content/plugins/...` URLs find nothing.

This check posts one info finding identifying the fork (so reports show
context) and writes the fork type to `ctx['shared']['wp_fork']` so
downstream checks can adjust their assumptions.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)

    # --- Try the REST root for the generator field (CP and WP both expose it).
    fork = "wordpress"
    detail = ""
    step("probing /wp-json/ for fork identifier...")
    r = await client.get("/wp-json/")
    if r is not None and r.status_code == 200:
        body = (r.text or "")[:50_000]
        if "ClassicPress" in body or "classicpress" in body.lower():
            fork = "classicpress"
            detail = "REST root advertises ClassicPress."
        # else: vanilla WP — the default classification already; nothing to do.

    # --- Bedrock layout: probe /app/themes/ + /app/plugins/. WP would 404.
    step("probing /app/themes/ for Bedrock layout...")
    bed_a = await client.head("/app/themes/")
    bed_b = await client.head("/app/plugins/")
    if fork == "wordpress" and bed_a is not None and bed_b is not None:
        # Both endpoints existing (200/301/302/403/Forbidden) instead of 404
        # is the Bedrock signal — vanilla WP doesn't have /app/.
        for resp in (bed_a, bed_b):
            if resp.status_code in (200, 301, 302, 307, 308, 401, 403):
                fork = "bedrock"
                detail = "Found /app/themes/ + /app/plugins/ — Bedrock (Roots) layout."
                break

    # --- Headless decoupled — Next.js _next / Gatsby static
    if fork == "wordpress":
        home = await client.get("/")
        if home is not None and home.text:
            body = home.text[:30_000].lower()
            if "/_next/" in body or "__next_data__" in body:
                fork = "headless-next"
                detail = "Detected Next.js front-end markers (_next, __NEXT_DATA__) — headless WP."
            elif "gatsby" in body or "data-gatsby" in body:
                fork = "headless-gatsby"
                detail = "Detected Gatsby markers — headless WP."
            elif "frontity" in body:
                fork = "headless-frontity"
                detail = "Detected Frontity markers — headless WP."

    # Persist for downstream checks
    shared = ctx.get("shared") or {}
    shared["wp_fork"] = fork
    ctx["shared"] = shared

    if fork == "wordpress":
        return [Finding(
            severity="info",
            title="WP fork detection: vanilla WordPress",
            evidence="No ClassicPress / Bedrock / headless markers detected.",
            remediation="No action needed.",
            url=ctx["target"],
        )]

    # Forks: emit an info finding with the detail + per-fork guidance.
    advice = {
        "classicpress": (
            "ClassicPress diverges from WP at the version field but shares the "
            "plugin ecosystem. Patchstack CVE matches still apply; CVE-IDs that "
            "are WP-core-specific need separate verification."
        ),
        "bedrock": (
            "Bedrock moves wp-config.php out of the web root and uses /app/ "
            "instead of /wp-content/. Several checks that probe /wp-content/ "
            "paths will under-report; verify findings via the running site's "
            "console rather than the URL probes."
        ),
        "headless-next":     "Front-end is Next.js. REST/GraphQL surface still "
                             "exposes the WP origin — those checks remain valid.",
        "headless-gatsby":   "Front-end is Gatsby. WP REST is consumed at build "
                             "time; runtime CVEs in WP still apply to the origin.",
        "headless-frontity": "Front-end is Frontity. Same caveat as Next/Gatsby.",
    }
    return [Finding(
        severity="info",
        title=f"WP fork detection: {fork}",
        evidence=detail,
        remediation=advice.get(fork, "No action needed."),
        url=ctx["target"],
        extra={"fork": fork},
    )]
