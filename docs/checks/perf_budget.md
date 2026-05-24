# Performance-budget audit (#25)

**check_id**: `perf_budget`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499 — Endpoint DoS
**CWE**: CWE-400
**D3FEND**: D3-NTA

## What it does

Round-60 #25 — performance-budget mode.

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
wpsecscan --target https://example.com --only perf_budget
```
