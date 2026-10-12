---
id: perf_budget
title: "Performance-budget audit (#25)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 157
---

# Performance-budget audit (#25)

**check_id**: `perf_budget`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499 — Endpoint DoS
**CWE**: CWE-400
**D3FEND**: D3-NTA

## What it does

Round-60 #25 — performance-budget mode.

Flags pages exceeding common perf budgets:
  - total transfer &gt; 3 MB
  - HTML &gt; 200 KB
  - &gt;50 third-party requests
  - LCP-likely image &gt; 500 KB inline or first &lt;img&gt; &gt; 200 KB
  - &gt;10 render-blocking &lt;link rel=stylesheet&gt;
  - Time-to-First-Byte &gt; 1.5s (when host responds quickly we can measure
    actual elapsed; we use the HTTP client's response.elapsed if exposed)

Pure HTML parsing — no headless browser needed. Use the round-O Playwright
recorder for real LCP / CLS metrics.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | First image &gt; 500 KB (⟨value⟩ KB) | Compress the LCP image (AVIF/WebP), serve a responsive srcset, preload it from &lt;head&gt;. |
| medium | Slow first-byte (⟨elapsed_ms⟩ ms) | Profile origin response time. Likely candidates: PHP-FPM tuning, missing edge cache, slow DB query on autoload options. |
| medium | ⟨count⟩ third-party JS requests | Audit each third-party. Defer non-critical (analytics, chat widgets). The biggest perf wins are in this list. |
| low | HTML &gt; 200 KB (⟨value⟩ KB) | Strip inline JSON-LD bloat, remove unused inline styles, lazy-load below-the-fold sections. |
| low | ⟨css_links⟩ render-blocking &lt;link rel=stylesheet&gt; | Concatenate CSS, defer non-critical with media=print + onload trick, inline critical CSS. |
| info | Perf budget — could not fetch home page | No action. |
| info | Perf budget — within budget | No action. |

## Evidence the check records

- Slow first-byte (⟨elapsed_ms⟩ ms): GET / took ⟨elapsed_ms⟩ms. Budget: &lt;1500ms.
- HTML &gt; 200 KB (⟨value⟩ KB): Home page HTML is ⟨value⟩ KB. Budget: &lt;200 KB.
- ⟨css_links⟩ render-blocking &lt;link rel=stylesheet&gt;: Counted ⟨css_links⟩ stylesheet links. Budget: &lt;10.
- ⟨count⟩ third-party JS requests: ⟨value⟩ ...
- Perf budget — within budget: TTFB=⟨elapsed_ms⟩ms, HTML=⟨value⟩KB, CSS-links=⟨css_links⟩, 3p-scripts=⟨count⟩, imgs=⟨count⟩.
- First image &gt; 500 KB (⟨value⟩ KB): &lt;img src='⟨value⟩'&gt; is ⟨value⟩ KB. Likely the LCP candidate.

## Compliance mapping

- **compliance_map / pci_dss**: 12.1
- **compliance_map / nist_800_53**: CP-2
- **compliance_map / iso_27001**: A.5.30
- **compliance_extra / hipaa**: 164.308(a)(7)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: CP-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: CP.L2-3.7.6
- **compliance_v2 / nist_csf**: PR.IR-04
- **compliance_v2 / cis_v8**: 11.3
- **compliance_v2 / iso_27001_2022**: A.5.30

## Run only this check

```
wpsecscan only perf_budget https://example.com
```

`only` runs this check alone and prints its findings.
