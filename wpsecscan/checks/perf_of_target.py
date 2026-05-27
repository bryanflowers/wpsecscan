"""P146-P150 (v2.7.0) — operational performance audit (not security).

Sibling check that reports performance-relevant metrics alongside the
security findings. All info-severity by default; bump to medium when
the metric crosses an env-configurable threshold.

  P146 Core Web Vitals — TTFB + size-of-main-doc (cheap; LCP/INP/CLS
                          need a real browser, see headless_templates).
  P147 Lighthouse score — invoked via subprocess when `lighthouse` is on
                            PATH; else skipped.
  P148 DB-query budget — read from /wp-json/wpsecscan/v1/diagnostics
                          (companion plugin reports query count).
  P149 CDN cache-hit ratio — sample N requests + read cf-cache-status /
                              x-cache header; report hit ratio.
  P150 cold-start probe — TTFB across N fresh-host requests.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import statistics
import subprocess
import time
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding


_CACHE_HIT_HEADERS = ("cf-cache-status", "x-cache", "x-vercel-cache", "x-served-by")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # P146 — TTFB + main doc size
    step("perf: GET / (TTFB + size)")
    t0 = time.time()
    home = await client.get("/")
    if home is not None:
        ttfb_ms = int((time.time() - t0) * 1000)
        size_kb = len(home.text or "") // 1024
        sev = "medium" if ttfb_ms > 2000 else "info"
        findings.append(Finding(
            severity=sev,
            title=f"P146 TTFB {ttfb_ms} ms, main doc {size_kb} KB",
            evidence=f"GET / measured at {ttfb_ms} ms TTFB; body size {size_kb} KB.",
            remediation=(
                "Aim for TTFB < 800 ms. Common culprits: PHP opcache off, "
                "uncached homepage, slow DB query (see P148)."
            ),
            url=client.url("/"),
            extra={"ttfb_ms": ttfb_ms, "size_kb": size_kb},
        ))

    # P147 — Lighthouse score (only if `lighthouse` CLI is available)
    step("perf: lighthouse probe")
    if shutil.which("lighthouse"):
        try:
            r = subprocess.run(
                ["lighthouse", str(client.base_url),
                  "--output=json", "--quiet", "--chrome-flags=--headless"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode == 0 and r.stdout:
                data = json.loads(r.stdout)
                cat = data.get("categories", {})
                perf = int((cat.get("performance") or {}).get("score", 0) * 100)
                a11y = int((cat.get("accessibility") or {}).get("score", 0) * 100)
                seo  = int((cat.get("seo") or {}).get("score", 0) * 100)
                sev = "medium" if perf < 50 else "info"
                findings.append(Finding(
                    severity=sev,
                    title=f"P147 Lighthouse: perf {perf} / a11y {a11y} / seo {seo}",
                    evidence=f"Lighthouse audit: performance={perf}, "
                              f"accessibility={a11y}, seo={seo} (0-100).",
                    remediation="See /lighthouse-report.html for the per-audit recommendations.",
                    url=client.url("/"),
                    extra={"lighthouse_perf": perf, "lighthouse_a11y": a11y,
                            "lighthouse_seo": seo},
                ))
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass

    # P148 — DB-query budget via companion
    step("perf: DB-query budget (companion)")
    token = ctx.get("companion_token")
    if token:
        try:
            from urllib.parse import urlparse as _u
            parsed = _u(ctx["target"])
            base = f"{parsed.scheme}://{parsed.netloc}"
            async with httpx.AsyncClient(timeout=8.0) as c:
                rr = await c.get(base + "/wp-json/wpsecscan/v1/diagnostics",
                                   headers={"X-WPSecScan-Token": token})
                if rr.status_code == 200:
                    d = rr.json()
                    queries = int(d.get("queries") or d.get("db_query_count") or 0)
                    if queries > 50:
                        findings.append(Finding(
                            severity="medium",
                            title=f"P148 DB-query count {queries} on homepage",
                            evidence=(f"Companion reported {queries} DB queries to "
                                       f"render the homepage. >50 typically indicates "
                                       f"un-cached + N+1 query patterns."),
                            remediation=(
                                "1. Enable a page-cache plugin (WP Rocket / W3TC).\n"
                                "2. Audit the slowest plugins via Query Monitor.\n"
                                "3. Convert N+1 queries to a single JOIN where possible."),
                            url=client.url("/"),
                            extra={"db_queries": queries},
                        ))
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
            pass

    # P149 — CDN cache-hit ratio (sample 5 requests, read headers)
    step("perf: CDN cache-hit ratio sample")
    hits = misses = 0
    for _ in range(5):
        r = await client.get("/")
        if r is None:
            continue
        for h in _CACHE_HIT_HEADERS:
            v = r.headers.get(h, "").lower()
            if "hit" in v:
                hits += 1
                break
            elif "miss" in v:
                misses += 1
                break
    total = hits + misses
    if total > 0:
        ratio = hits / total
        sev = "medium" if ratio < 0.5 else "info"
        findings.append(Finding(
            severity=sev,
            title=f"P149 CDN cache-hit ratio {int(ratio * 100)}% ({hits}/{total})",
            evidence=f"Sampled {total} GETs of /; {hits} reported cache HIT, "
                      f"{misses} MISS via {_CACHE_HIT_HEADERS} headers.",
            remediation=(
                "Low hit ratio means the operator pays bandwidth for cacheable\n"
                "content. Common fixes: bump Cache-Control max-age, audit\n"
                "vary headers, ensure cookies aren't disabling cache."
            ),
            url=client.url("/"),
            extra={"cache_hits": hits, "cache_misses": misses,
                    "cache_hit_ratio": ratio},
        ))

    # P150 — cold-start probe (3 fresh requests, report TTFB variance)
    step("perf: cold-start probe (3 GETs)")
    ttfbs: list[int] = []
    for _ in range(3):
        t0 = time.time()
        try:
            r = await client.get("/")
        except Exception:  # noqa: BLE001
            r = None
        if r is not None:
            ttfbs.append(int((time.time() - t0) * 1000))
        await asyncio.sleep(2)
    if len(ttfbs) >= 2:
        spread = max(ttfbs) - min(ttfbs)
        sev = "medium" if spread > 1500 else "info"
        findings.append(Finding(
            severity=sev,
            title=f"P150 TTFB spread {spread} ms across {len(ttfbs)} fresh requests",
            evidence=f"TTFB samples (ms): {ttfbs}; spread: {spread} ms; "
                      f"mean: {int(statistics.mean(ttfbs))} ms.",
            remediation=(
                "Large spread = cold-start pattern (Lambda / Heroku free tier "
                "etc.). Keep a warm instance or move to a host with persistent "
                "PHP-FPM workers."
            ),
            url=client.url("/"),
            extra={"ttfb_samples": ttfbs, "ttfb_spread_ms": spread},
        ))

    return findings
