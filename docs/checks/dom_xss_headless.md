---
id: dom_xss_headless
title: "Headless DOM-XSS (Playwright, opt-in)"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Privacy, compliance & accessibility"
words: 263
---

# Headless DOM-XSS (Playwright, opt-in)

**check_id**: `dom_xss_headless`
**aggressive**: yes
**category**: Privacy, compliance & accessibility
**max severity**: critical
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

## Request footprint

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | CONFIRMED client-side DOM-XSS (⟨count⟩ URL(s)) | Find the JS that reads location.search / URLSearchParams and writes the value into innerHTML, document.write, eval, setTimeout(string), Function(string), or jQuery.html(). Replace with .textContent, escape the value, or use a strict allow-list. Add a strong CSP that bans 'unsafe-inline' to make exploitation harder. |
| info | Headless DOM-XSS probe failed | Re-install Playwright: pip install playwright && playwright install chromium |
| info | Headless DOM-XSS probe skipped (Playwright not installed) | No action needed unless you want client-side XSS coverage. Server-side reflected XSS is still tested by the regular xss check. |
| info | Headless DOM-XSS probe skipped (passive mode) | No action. |
| info | No client-side DOM-XSS markers fired | No action. |

## Evidence the check records

- CONFIRMED client-side DOM-XSS (⟨count⟩ URL(s)): Headless browser executed our marker payload after navigating to: ⟨value⟩ The URL parameter is written into a script/event-handler context without sanitisation.
- Headless DOM-XSS probe skipped (Playwright not installed): WPSecScan can drive a real headless Chromium to catch client-side XSS that static curl-based probes inherently miss (DOM-sink injection that only fires after JS evaluates URL parameters). To enable, install Playwright in the same Python environment: pip install playwright playwright install chromium Note: Playwright adds ~250MB of browser binaries — it's optional.
- Headless DOM-XSS probe skipped (passive mode): Run with --aggressive to enable.
- No client-side DOM-XSS markers fired: Drove headless Chromium across ⟨count⟩ pages × ⟨count⟩ parameters × ⟨count⟩ payloads. None caused window.__wpsec to be set, suggesting the homepage's URL parameters aren't directly written into a script context.
- Headless DOM-XSS probe failed: Playwright error: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-community/attacks/DOM_Based_XSS
- deep dive: https://portswigger.net/web-security/cross-site-scripting/dom-based

## Run only this check

```
wpsecscan only dom_xss_headless https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
