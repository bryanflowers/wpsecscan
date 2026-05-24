# Headless DOM-XSS (Playwright, opt-in)

**check_id**: `dom_xss_headless`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution
**CWE**: CWE-79
**D3FEND**: D3-IVA

## What it does

A7 Headless DOM-XSS detection (optional Playwright).

When Playwright isn't installed, this check emits an info finding explaining
how to enable it. When Playwright IS installed, it loads a curated list of
URLs (the scanner's discovered surface + a few canonical XSS vectors) into
a real headless browser and watches for:

  - Uncaught JS exceptions that mention attacker-controlled input
  - alert/prompt/confirm dialogs triggered by injected payloads
  - DOM mutations that wrote our marker into a script/event-handler context

This catches client-side XSS that static scanners (curl-based) inherently
cannot — the payload only fires when JS actually evaluates DOM nodes
constructed from URL parameters.

Defensive use only: tests the user's OWN site for unfilterable client-side
sinks, doesn't auto-exfiltrate or chain to credential theft.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only dom_xss_headless
```
