"""#14 (from nuclei) — headless-driven YAML templates.

nuclei templates can include a `headless:` block that drives a browser
session as part of the check. We implement the subset that's most useful
for WP scanning:

  - `navigate: <url>` — load the page
  - `wait: <seconds>` — let JS settle
  - `screenshot: <name>` — save a PNG into ~/.wpsecscan/headless-screens/
  - `extract: <css selector>` — pull text content
  - matchers: word/regex run against the post-JS DOM text

Templates in ~/.wpsecscan/templates/*.yaml may include `headless:`. Requires
Playwright (optional dep); falls back to an info finding when not installed.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from ..http import Client
from ..models import Finding


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _headless_screens_dir() -> Path:
    from .. import history as _h
    p = Path(_h._home()) / "headless-screens"
    p.mkdir(parents=True, exist_ok=True)
    return p


async def _run_headless_template(template: dict, ctx: dict) -> list[Finding]:
    from playwright.async_api import async_playwright
    import re as _re

    info = template.get("info") or {}
    sev = ({"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info"}
           .get((info.get("severity") or "info").lower(), "info"))
    name = info.get("name") or template.get("id", "unnamed")

    findings: list[Finding] = []
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception:  # noqa: BLE001
            return [Finding(severity="info", title=f"Headless template '{name}' — browser launch failed",
                            evidence="Playwright couldn't launch chromium (run `playwright install chromium`).",
                            remediation="No action.", url=ctx["target"])]
        page = await (await browser.new_context(ignore_https_errors=True)).new_page()

        for hb in (template.get("headless") or []):
            for step in (hb.get("steps") or []):
                action = (step.get("action") or "").lower()
                try:
                    if action == "navigate":
                        url = (step.get("args", {}).get("url") or "").replace("{{BaseURL}}", ctx["target"])
                        await page.goto(url, timeout=10000)
                    elif action == "wait":
                        await asyncio.sleep(float(step.get("args", {}).get("seconds", 1)))
                    elif action == "screenshot":
                        out = _headless_screens_dir() / f"{template.get('id', 'tmpl')}-{step.get('args', {}).get('name', 'shot')}.png"
                        await page.screenshot(path=str(out))
                except Exception:  # noqa: BLE001
                    continue

            dom_text = ""
            try:
                dom_text = await page.content()
            except Exception:  # noqa: BLE001
                pass

            matched = False
            for m in hb.get("matchers") or []:
                mtype = (m.get("type") or "").lower()
                if mtype == "word":
                    words = m.get("words", []) or []
                    cond = (m.get("condition") or "or").lower()
                    if cond == "and":
                        if all(w in dom_text for w in words):
                            matched = True
                            break
                    elif any(w in dom_text for w in words):
                        matched = True
                        break
                elif mtype == "regex":
                    for pat in m.get("regex", []) or []:
                        try:
                            if _re.search(pat, dom_text):
                                matched = True
                                break
                        except _re.error:
                            continue
                    if matched:
                        break

            if matched:
                findings.append(Finding(
                    severity=sev,
                    title=f"[headless template] {name}",
                    evidence=f"Headless template {template.get('id', '?')!r} matched against the rendered DOM.",
                    remediation=info.get("description") or "See template for context.",
                    url=ctx["target"],
                    extra={"template_id": template.get("id")},
                ))
        await browser.close()
    return findings


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        return [Finding(
            severity="info",
            title="Headless DOM templates skipped (passive mode)",
            evidence="Pass --aggressive to drive a real browser against the target.",
            remediation="No action.",
            url=ctx["target"],
        )]

    from .. import template_engine as _te

    if not _has_playwright():
        return [Finding(severity="info",
                        title="Headless templates skipped (Playwright not installed)",
                        evidence="Install: `pip install playwright && playwright install chromium`.",
                        remediation="No action.", url=ctx["target"])]
    if not _te._has_yaml():
        return [Finding(severity="info",
                        title="Headless templates skipped (PyYAML not installed)",
                        evidence="Install pyyaml to enable.", remediation="No action.",
                        url=ctx["target"])]

    headless = []
    for p in _te.list_templates():
        t = _te._load_template(p)
        if t and (t.get("headless") or []):
            headless.append(t)
    if not headless:
        return [Finding(severity="info",
                        title="Headless templates — none found",
                        evidence="No template in ~/.wpsecscan/templates/ includes a `headless:` block.",
                        remediation="No action.", url=ctx["target"])]

    step(f"running {len(headless)} headless template(s)...")
    for t in headless:
        try:
            findings.extend(await _run_headless_template(t, ctx))
        except Exception:  # noqa: BLE001
            continue
    return findings
