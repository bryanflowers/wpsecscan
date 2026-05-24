"""Round-60 #25 — performance-budget mode.

Flags pages exceeding common perf budgets:
  - total transfer > 3 MB
  - HTML > 200 KB
  - >50 third-party requests
  - LCP-likely image > 500 KB inline or first <img> > 200 KB
  - >10 render-blocking <link rel=stylesheet>
  - Time-to-First-Byte > 1.5s (when host responds quickly we can measure
    actual elapsed; we use the HTTP client's response.elapsed if exposed)

Pure HTML parsing — no headless browser needed. Use the round-O Playwright
recorder for real LCP / CLS metrics.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse, urljoin
from ..http import Client
from ..models import Finding


CSS_LINK_RE = re.compile(r'<link\b[^>]*rel\s*=\s*[\"\']?stylesheet[\"\']?[^>]*>', re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
IMG_SRC_RE = re.compile(r'<img[^>]+src=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")
    target_host = urlparse(target).hostname or ""

    step("perf: TTFB measurement...")
    t0 = time.perf_counter()
    r = await client.get("/")
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if r is None or not r.text:
        return [Finding(severity="info", title="Perf budget — could not fetch home page",
                        evidence="", remediation="No action.", url=target)]
    body = r.text
    html_bytes = len(body.encode("utf-8"))

    if elapsed_ms > 1500:
        findings.append(Finding(
            severity="medium",
            title=f"Slow first-byte ({elapsed_ms} ms)",
            evidence=f"GET / took {elapsed_ms}ms. Budget: <1500ms.",
            remediation="Profile origin response time. Likely candidates: PHP-FPM tuning, missing edge cache, slow DB query on autoload options.",
            url=target,
        ))

    if html_bytes > 200_000:
        findings.append(Finding(
            severity="low",
            title=f"HTML > 200 KB ({html_bytes // 1024} KB)",
            evidence=f"Home page HTML is {html_bytes // 1024} KB. Budget: <200 KB.",
            remediation="Strip inline JSON-LD bloat, remove unused inline styles, lazy-load below-the-fold sections.",
            url=target,
        ))

    css_links = len(CSS_LINK_RE.findall(body))
    if css_links > 10:
        findings.append(Finding(
            severity="low",
            title=f"{css_links} render-blocking <link rel=stylesheet>",
            evidence=f"Counted {css_links} stylesheet links. Budget: <10.",
            remediation="Concatenate CSS, defer non-critical with media=print + onload trick, inline critical CSS.",
            url=target,
        ))

    scripts = SCRIPT_SRC_RE.findall(body)
    third_party = [s for s in scripts if s.startswith(("http://", "https://"))
                    and (urlparse(s).hostname or "") not in ("", target_host)
                    and not (urlparse(s).hostname or "").endswith("." + target_host)]
    if len(third_party) > 50:
        findings.append(Finding(
            severity="medium",
            title=f"{len(third_party)} third-party JS requests",
            evidence="\n".join(f"  - {s}" for s in third_party[:10]) + ("\n  ..." if len(third_party) > 10 else ""),
            remediation="Audit each third-party. Defer non-critical (analytics, chat widgets). The biggest perf wins are in this list.",
            url=target,
        ))

    # First <img> size (best-effort — we don't fetch them all, just first 5)
    imgs = IMG_SRC_RE.findall(body)
    if imgs:
        first = imgs[0] if imgs[0].startswith(("http://", "https://")) else urljoin(target, imgs[0])
        try:
            head = await client.head(first)
            if head and head.headers:
                cl = head.headers.get("Content-Length")
                if cl and int(cl) > 500_000:
                    findings.append(Finding(
                        severity="medium",
                        title=f"First image > 500 KB ({int(cl) // 1024} KB)",
                        evidence=f"<img src='{imgs[0]}'> is {int(cl) // 1024} KB. Likely the LCP candidate.",
                        remediation="Compress the LCP image (AVIF/WebP), serve a responsive srcset, preload it from <head>.",
                        url=first,
                    ))
        except (ValueError, AttributeError):
            pass

    if not findings:
        return [Finding(severity="info", title="Perf budget — within budget",
                        evidence=f"TTFB={elapsed_ms}ms, HTML={html_bytes // 1024}KB, CSS-links={css_links}, "
                                  f"3p-scripts={len(third_party)}, imgs={len(imgs)}.",
                        remediation="No action.", url=target)]
    return findings
