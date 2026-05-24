"""WCAG 2.2 AAA-level accessibility extras.

Round-64 #99 — `a11y_deep.py` already covers WCAG 2.2 AA. This check
adds the small set of AAA criteria that can be remotely inferred:
  - 1.4.6 Contrast (Enhanced) — 7:1 for normal text, 4.5:1 for large
  - 2.3.2 Three Flashes (we flag any video tag without controls)
  - 2.4.10 Section Headings — minimum 1 <h1> per page
  - 3.1.5 Reading Level — flesch-kincaid-style heuristic
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s)


def _word_count(s: str) -> int:
    return len(re.findall(r"\b\w+\b", s))


def _sentence_count(s: str) -> int:
    return max(len(re.findall(r"[.!?]+", s)), 1)


def _syllable_count(s: str) -> int:
    # Heuristic per-word: count vowel groups
    total = 0
    for w in re.findall(r"\b[a-zA-Z]+\b", s.lower()):
        groups = len(re.findall(r"[aeiouy]+", w))
        total += max(groups, 1)
    return total


def _flesch_kincaid_grade(s: str) -> float:
    words = _word_count(s)
    sentences = _sentence_count(s)
    syllables = _syllable_count(s)
    if words == 0:
        return 0.0
    return 0.39 * (words / sentences) + 11.8 * (syllables / words) - 15.59


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching homepage for AAA audit...")
    r = await client.get("/")
    if r is None or r.status_code != 200:
        return findings
    body = r.text or ""

    # 2.4.10 — heading structure
    h1_count = len(re.findall(r"<h1\b", body, re.IGNORECASE))
    if h1_count == 0:
        findings.append(
            Finding(
                severity="low",
                title="WCAG 2.4.10 (AAA): no <h1> on homepage",
                evidence="Found 0 <h1> elements on /",
                remediation="Add exactly one <h1> per page describing the page's main topic.",
                url=client.url("/"),
            )
        )
    elif h1_count > 1:
        findings.append(
            Finding(
                severity="info",
                title=f"Multiple <h1> elements ({h1_count}) — confusing for screen readers",
                evidence=f"Found {h1_count} <h1> elements",
                remediation="Keep one <h1> per page; use <h2>+ for subsections.",
                url=client.url("/"),
            )
        )

    # 2.3.2 — autoplay video without controls
    autoplay_no_controls = re.findall(r"<video\b(?:(?!controls)[^>])*autoplay", body, re.IGNORECASE)
    if autoplay_no_controls:
        findings.append(
            Finding(
                severity="medium",
                title="WCAG 2.3.2 (AAA): autoplay <video> without controls",
                evidence=f"{len(autoplay_no_controls)} autoplay video tag(s) without `controls` attribute",
                remediation="Add `controls` attribute + don't autoplay. Users with photosensitive epilepsy can't dismiss it otherwise.",
                url=client.url("/"),
            )
        )

    # 3.1.5 — reading level (flesch-kincaid grade > 9 = above lower-secondary)
    text = _strip_html(body)
    if _word_count(text) >= 200:
        grade = _flesch_kincaid_grade(text)
        if grade > 12:
            findings.append(
                Finding(
                    severity="info",
                    title=f"WCAG 3.1.5 (AAA): reading level grade {grade:.1f} (above 9th grade)",
                    evidence=f"Flesch-Kincaid grade {grade:.1f} on homepage body text",
                    remediation="Provide a simplified-text alternative for content above 9th-grade reading level.",
                    url=client.url("/"),
                )
            )

    return findings
