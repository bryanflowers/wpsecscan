"""Lightweight accessibility (a11y) smoke check.

NOT a replacement for axe-core or Lighthouse — just a quick "is this site
missing the basics" check. Three rules:
  1. <html> must have lang=
  2. All <img> on the homepage must have alt= (empty alt is OK; missing isn't)
  3. The page must have a <title>

Why ship this? ADA Title III (US) and EU EAA (June 2025) increasingly turn
basic a11y misses into legal liability. Scanner users who run wpsecscan on
their own sites benefit from a heads-up.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

IMG_RE = re.compile(r"<img\b([^>]*)>", re.IGNORECASE)
ALT_RE = re.compile(r'\balt\s*=\s*(["\']).*?\1', re.IGNORECASE)
HTML_LANG_RE = re.compile(r"<html\b([^>]*)>", re.IGNORECASE)
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("inspecting / for a11y basics...")
    r = await client.get("/")
    if r is None or not r.text:
        findings.append(
            Finding(
                severity="info",
                title="a11y check skipped — / didn't return HTML",
                evidence="GET / returned no body.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    html = r.text
    issues: list[str] = []

    # 1. <html lang=...>
    m = HTML_LANG_RE.search(html)
    if m and "lang=" not in m.group(1).lower():
        issues.append("`<html>` tag is missing a `lang=` attribute. Screen readers fall back to "
                      "the user's OS locale, which silently mispronounces non-matching content.")

    # 2. Images without alt
    images = IMG_RE.findall(html[:200000])  # cap at 200 KB
    no_alt = [img for img in images if not ALT_RE.search(img)]
    if no_alt:
        issues.append(
            f"{len(no_alt)} of {len(images)} `<img>` tag(s) on the homepage are missing `alt=`. "
            "Use `alt=\"\"` for decorative images; meaningful alt text for content images."
        )

    # 3. <title>
    title_m = TITLE_RE.search(html)
    if not title_m or not title_m.group(1).strip():
        issues.append("Page is missing a non-empty `<title>` — required for screen-reader tab navigation.")

    if not issues:
        findings.append(
            Finding(
                severity="info",
                title="a11y smoke check passed (homepage)",
                evidence=f"<html lang=> ✓ · {len(images)} images all have alt= ✓ · <title> ✓",
                remediation=(
                    "No action from this smoke check, but run a real audit (Lighthouse, axe DevTools, "
                    "or pa11y) for WCAG 2.1 AA compliance."
                ),
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="low",
            title=f"a11y smoke check flagged {len(issues)} basic issue(s)",
            evidence="\n".join(f"  • {x}" for x in issues),
            remediation=(
                "These are the lowest bar of accessibility. Run a full audit (Lighthouse, axe DevTools, pa11y) "
                "for WCAG 2.1 AA conformance — increasingly required by ADA Title III (US) and the EU "
                "European Accessibility Act (from June 2025)."
            ),
            url=ctx["target"],
        )
    )
    return findings
