"""I11 Per-finding screenshot capture (optional Playwright).

When Playwright is installed, capture one screenshot per critical / high
finding (limited to the first 10) and embed them as base64 data: URIs in
the HTML report. Helps non-technical stakeholders see proof of impact
without having to re-run a browser session.

When Playwright is NOT installed, this module is a no-op — no error, no
warning. The HTML report renders as normal without screenshots.
"""
from __future__ import annotations

import asyncio
import base64
from typing import Any

from .models import ScanReport, Finding


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def _capture_one(page, url: str, timeout_ms: int = 8000) -> str | None:
    try:
        await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
        png = await page.screenshot(full_page=False, timeout=timeout_ms)
        return base64.b64encode(png).decode("ascii")
    except Exception:  # noqa: BLE001
        return None


async def capture_findings(report: ScanReport, *, limit: int = 10) -> dict[str, str]:
    """Return {finding_key: base64_png_data}. finding_key = "{check_id}::{title}".

    Captures up to `limit` of the highest-severity findings that have a URL.
    """
    if not _has_playwright():
        return {}

    from playwright.async_api import async_playwright
    from .models import SEVERITY_RANK

    candidates: list[tuple[str, Finding]] = []
    for r in report.results:
        for f in r.findings:
            if not f.url or f.severity not in ("critical", "high"):
                continue
            candidates.append((r.check_id, f))
    candidates.sort(key=lambda x: -SEVERITY_RANK.get(x[1].severity, -1))
    candidates = candidates[:limit]
    if not candidates:
        return {}

    out: dict[str, str] = {}
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception:  # noqa: BLE001
            return {}
        ctx_ = await browser.new_context(ignore_https_errors=True,
                                          viewport={"width": 1280, "height": 720})
        page = await ctx_.new_page()
        for cid, f in candidates:
            key = f"{cid}::{f.title}"
            data = await _capture_one(page, f.url)
            if data:
                out[key] = data
        await ctx_.close()
        await browser.close()
    if out:
        try:
            from . import activity as _act
            _act.emit("artifact", f"screenshots captured: {len(out)} critical/high finding(s)")
        except ImportError:
            pass
    return out


def capture_sync(report: ScanReport, limit: int = 10) -> dict[str, str]:
    """Sync wrapper. Returns {} when Playwright isn't available."""
    if not _has_playwright():
        return {}
    try:
        return asyncio.run(capture_findings(report, limit=limit))
    except RuntimeError:
        # Already inside an event loop — bail out, screenshots are optional
        return {}
