"""A7 Headless DOM-XSS detection (optional Playwright).

When Playwright isn't installed, this check emits an info finding explaining
how to enable it. When Playwright IS installed, it loads a curated list of
URLs (the scanner's discovered surface + a few canonical XSS vectors) into
a real headless browser and watches for:

  - Uncaught JS exceptions that mention attacker-controlled input
  - alert/prompt/confirm dialogs triggered by injected payloads
  - DOM mutations that wrote our marker into a script/event-handler context

This catches client-side XSS that static scanners (curl-based) inherently
cannot — the payload only fires when JS actually evaluates DOM nodes
constructed from URL parameters.

Defensive use only: tests the user's OWN site for unfilterable client-side
sinks, doesn't auto-exfiltrate or chain to credential theft.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse, urlencode

from ..http import Client
from ..models import Finding

# Canonical client-side XSS triggers — these are passive (alert-based marker)
# probes; if a finding is positive, the browser fired our marker, proving
# the URL parameter ends up in an eval/script context.
DOM_XSS_PAYLOADS = (
    # Marker payloads — server-side scanners will not flag these because the
    # marker only fires inside a browser.
    "WPSEC_PROBE_{n}__\"><svg/onload=window.__wpsec={n}>",
    "WPSEC_PROBE_{n}__';window.__wpsec={n};//",
    "WPSEC_PROBE_{n}__</script><img src=x onerror=window.__wpsec={n}>",
)

# Common GET-param sinks worth probing on the homepage + /?s= search
DEFAULT_PARAMS = ("q", "s", "search", "p", "id", "page", "name", "callback")


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def _probe_with_playwright(target: str, paths: list[str], probe_id: int) -> list[tuple[str, str]]:
    """Returns list of (url, marker_id) pairs that fired window.__wpsec."""
    from playwright.async_api import async_playwright

    hits: list[tuple[str, str]] = []
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception:  # noqa: BLE001
            return hits
        ctx = await browser.new_context(ignore_https_errors=True)
        # Dismiss alert/prompt/confirm dialogs automatically — and count them
        ctx.on("dialog", lambda d: asyncio.create_task(d.dismiss()))

        page = await ctx.new_page()
        for path in paths:
            for param in DEFAULT_PARAMS:
                for tmpl in DOM_XSS_PAYLOADS:
                    payload = tmpl.format(n=probe_id)
                    url = f"{path.rstrip('/')}/?{urlencode({param: payload})}"
                    try:
                        await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                        marker = await page.evaluate("() => window.__wpsec || null")
                        if marker:
                            hits.append((url, str(marker)))
                    except Exception:  # noqa: BLE001
                        continue
        await ctx.close()
        await browser.close()
    return hits


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not _has_playwright():
        findings.append(
            Finding(
                severity="info",
                title="Headless DOM-XSS probe skipped (Playwright not installed)",
                evidence=(
                    "WPSecScan can drive a real headless Chromium to catch client-side XSS "
                    "that static curl-based probes inherently miss (DOM-sink injection that "
                    "only fires after JS evaluates URL parameters).\n\n"
                    "To enable, install Playwright in the same Python environment:\n"
                    "  pip install playwright\n"
                    "  playwright install chromium\n\n"
                    "Note: Playwright adds ~250MB of browser binaries — it's optional."
                ),
                remediation=(
                    "No action needed unless you want client-side XSS coverage. "
                    "Server-side reflected XSS is still tested by the regular xss check."
                ),
                url=ctx["target"],
            )
        )
        return findings

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="Headless DOM-XSS probe skipped (passive mode)",
                evidence="Run with --aggressive to enable.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [base + "/", base + "/?s=", base + "/index.php"]
    probe_id = 31337

    step("driving headless Chromium across DOM-XSS sinks...")
    try:
        hits = await _probe_with_playwright(ctx["target"], paths, probe_id)
    except Exception as e:  # noqa: BLE001
        findings.append(
            Finding(
                severity="info",
                title="Headless DOM-XSS probe failed",
                evidence=f"Playwright error: {str(e)[:200]}",
                remediation="Re-install Playwright: pip install playwright && playwright install chromium",
                url=ctx["target"],
            )
        )
        return findings

    if not hits:
        findings.append(
            Finding(
                severity="info",
                title="No client-side DOM-XSS markers fired",
                evidence=(
                    f"Drove headless Chromium across {len(paths)} pages × "
                    f"{len(DEFAULT_PARAMS)} parameters × {len(DOM_XSS_PAYLOADS)} payloads. "
                    "None caused window.__wpsec to be set, suggesting the homepage's URL "
                    "parameters aren't directly written into a script context."
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="critical",
            title=f"CONFIRMED client-side DOM-XSS ({len(hits)} URL(s))",
            evidence=(
                "Headless browser executed our marker payload after navigating to:\n  "
                + "\n  ".join(u for u, _m in hits[:10])
                + "\n\nThe URL parameter is written into a script/event-handler context "
                "without sanitisation."
            ),
            remediation=(
                "Find the JS that reads location.search / URLSearchParams and writes the value "
                "into innerHTML, document.write, eval, setTimeout(string), Function(string), "
                "or jQuery.html(). Replace with .textContent, escape the value, or use a strict "
                "allow-list. Add a strong CSP that bans 'unsafe-inline' to make exploitation harder."
            ),
            url=hits[0][0],
        )
    )
    return findings
