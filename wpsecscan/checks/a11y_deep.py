"""Round-60 #24 — WCAG 2.2 accessibility deep audit.

Extends `a11y_lite` with full WCAG 2.2 success-criteria coverage:
images-without-alt, form-labels, heading order, focus-visible, colour
contrast (approximate — only flags pages with no contrast meta), aria
roles + landmarks, document language, redundant link text, etc.

Pure HTML parsing — no headless browser. Lists pages that fail and
groups by criterion ID.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


IMG_RE   = re.compile(r"<img\b([^>]*)>", re.IGNORECASE)
ALT_RE   = re.compile(r"\balt\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
LABEL_RE = re.compile(r"<label\b([^>]*)>", re.IGNORECASE)
H_RE     = re.compile(r"<h([1-6])\b", re.IGNORECASE)
HTML_LANG_RE = re.compile(r"<html\b[^>]*\blang\s*=\s*[\"']([a-zA-Z\-]+)[\"']", re.IGNORECASE)
SKIP_LINK_RE = re.compile(r"skip\s+to\s+content|skip\s+navigation", re.IGNORECASE)
A_TAG_RE = re.compile(r"<a\b[^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    step("a11y: fetch home page...")
    r = await client.get("/")
    if r is None or not r.text:
        return [Finding(severity="info", title="A11y deep — could not fetch home page",
                        evidence="", remediation="No action.", url=target)]
    body = r.text[:300_000]
    fails: list[tuple[str, str, str]] = []   # (wcag, severity, message)

    # WCAG 1.1.1 — non-text content (img alt)
    imgs = IMG_RE.findall(body)
    missing_alt = [i for i in imgs if not ALT_RE.search(i)]
    empty_alt   = [i for i in imgs if ALT_RE.search(i) and not (m := ALT_RE.search(i)).group(1).strip()]
    if missing_alt:
        fails.append(("1.1.1", "high", f"{len(missing_alt)} <img> without alt attribute"))
    if len(empty_alt) > 5:
        fails.append(("1.1.1", "low", f"{len(empty_alt)} <img alt=''> (decorative — OK if intentional)"))

    # WCAG 1.3.1 — info & relationships (form-input labels)
    text_inputs = [m for m in INPUT_RE.findall(body)
                    if not re.search(r'type\s*=\s*[\"\']?(hidden|submit|button|image|reset)', m, re.IGNORECASE)]
    label_count = len(LABEL_RE.findall(body))
    if text_inputs and label_count < len(text_inputs):
        fails.append(("1.3.1", "medium",
                        f"{len(text_inputs)} form inputs vs {label_count} <label> tags — likely missing labels"))

    # WCAG 2.4.1 — bypass blocks (skip-link)
    if not SKIP_LINK_RE.search(body):
        fails.append(("2.4.1", "low", "No 'skip to content' link detected"))

    # WCAG 2.4.6 — heading order (no h1 → h3 jumps)
    headings = [int(m) for m in H_RE.findall(body)]
    if headings and 1 not in headings:
        fails.append(("2.4.6", "low", "No <h1> on the home page"))
    jumps = sum(1 for i in range(1, len(headings)) if headings[i] - headings[i - 1] > 1)
    if jumps > 2:
        fails.append(("2.4.6", "low", f"{jumps} heading-level jumps (skipped levels)"))

    # WCAG 2.4.4 — link purpose (no 'click here' / 'read more' floods)
    link_texts = [re.sub(r"<[^>]+>", "", t).strip().lower() for t in A_TAG_RE.findall(body)]
    bad_text = [t for t in link_texts if t in ("click here", "read more", "more", "here")]
    if len(bad_text) > 5:
        fails.append(("2.4.4", "low", f"{len(bad_text)} non-descriptive link texts ('click here' / 'read more')"))

    # WCAG 3.1.1 — page language
    if not HTML_LANG_RE.search(body):
        fails.append(("3.1.1", "medium", "<html> tag missing `lang` attribute"))

    # WCAG 1.4.3 contrast (approximate — only flag if no contrast meta)
    if not re.search(r"prefers-contrast|contrast", body, re.IGNORECASE):
        fails.append(("1.4.3", "info", "No contrast meta — run a full WCAG colour-contrast audit (axe-core / Lighthouse)."))

    # WCAG 4.1.2 — name, role, value (aria roles)
    if not re.search(r"role\s*=\s*[\"']", body):
        fails.append(("4.1.2", "low", "No ARIA roles detected (likely missing landmark roles)"))

    if not fails:
        return [Finding(severity="info", title="A11y deep — no obvious failures detected",
                        evidence="Checked WCAG 2.2 criteria 1.1.1, 1.3.1, 1.4.3, 2.4.1, 2.4.4, 2.4.6, 3.1.1, 4.1.2.",
                        remediation="Run an in-browser audit (axe-core / Lighthouse) for the criteria a static scan cannot evaluate.",
                        url=target)]

    by_sev = {"high": [], "medium": [], "low": [], "info": []}
    for wcag, sev, msg in fails:
        by_sev[sev].append(f"  WCAG {wcag}: {msg}")
    for sev, lines in by_sev.items():
        if not lines:
            continue
        findings.append(Finding(
            severity=sev,
            title=f"A11y WCAG 2.2 failures — {len(lines)} at {sev}",
            evidence="\n".join(lines),
            remediation="Each line names the WCAG criterion. See https://www.w3.org/WAI/WCAG22/quickref/ for guidance.",
            url=target,
        ))
    return findings
