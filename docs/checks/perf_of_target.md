---
id: perf_of_target
title: "Operational perf audit: TTFB / Lighthouse / DB-queries / cache-hit / cold-start (P146-P150)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 202
---

# Operational perf audit: TTFB / Lighthouse / DB-queries / cache-hit / cold-start (P146-P150)

**check_id**: `perf_of_target`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: n/a — Operational
**MITRE ATT&CK**: n/a — Performance audit
**CWE**: CWE-400
**D3FEND**: D3-NTA

## What it does

P146-P150 (v2.7.0) — operational performance audit (not security).

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

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/info | P146 TTFB ⟨ttfb_ms⟩ ms, main doc ⟨size_kb⟩ KB | Aim for TTFB &lt; 800 ms. Common culprits: PHP opcache off, uncached homepage, slow DB query (see P148). |
| medium/info | P147 Lighthouse: perf ⟨perf⟩ / a11y ⟨a11y⟩ / seo ⟨seo⟩ | See /lighthouse-report.html for the per-audit recommendations. |
| medium | P148 DB-query count ⟨queries⟩ on homepage | 1. Enable a page-cache plugin (WP Rocket / W3TC). 2. Audit the slowest plugins via Query Monitor. 3. Convert N+1 queries to a single JOIN where possible. |
| medium/info | P149 CDN cache-hit ratio ⟨value⟩% (⟨hits⟩/⟨total⟩) | Low hit ratio means the operator pays bandwidth for cacheable content. Common fixes: bump Cache-Control max-age, audit vary headers, ensure cookies aren't disabling cache. |
| medium/info | P150 TTFB spread ⟨spread⟩ ms across ⟨count⟩ fresh requests | Large spread = cold-start pattern (Lambda / Heroku free tier etc.). Keep a warm instance or move to a host with persistent PHP-FPM workers. |

## Evidence the check records

- P146 TTFB ⟨ttfb_ms⟩ ms, main doc ⟨size_kb⟩ KB: GET / measured at ⟨ttfb_ms⟩ ms TTFB; body size ⟨size_kb⟩ KB.
- P149 CDN cache-hit ratio ⟨value⟩% (⟨hits⟩/⟨total⟩): Sampled ⟨total⟩ GETs of /; ⟨hits⟩ reported cache HIT, ⟨misses⟩ MISS via ⟨_CACHE_HIT_HEADERS⟩ headers.
- P150 TTFB spread ⟨spread⟩ ms across ⟨count⟩ fresh requests: TTFB samples (ms): ⟨ttfbs⟩; spread: ⟨spread⟩ ms; mean: ⟨value⟩ ms.
- P147 Lighthouse: perf ⟨perf⟩ / a11y ⟨a11y⟩ / seo ⟨seo⟩: Lighthouse audit: performance=⟨perf⟩, accessibility=⟨a11y⟩, seo=⟨seo⟩ (0-100).
- P148 DB-query count ⟨queries⟩ on homepage: Companion reported ⟨queries⟩ DB queries to render the homepage. &gt;50 typically indicates un-cached + N+1 query patterns.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: n/a
- **compliance_map / iso_27001**: n/a

## Run only this check

```
wpsecscan only perf_of_target https://example.com
```

`only` runs this check alone and prints its findings.
