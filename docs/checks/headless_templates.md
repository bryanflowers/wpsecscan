---
id: headless_templates
title: "Headless DOM templates (Playwright) (#14)"
severity_max: info
severity_dynamic: true
aggressive: true
category: "GraphQL & APIs"
words: 178
---

# Headless DOM templates (Playwright) (#14)

**check_id**: `headless_templates`
**aggressive**: yes
**category**: GraphQL & APIs
**max severity**: info (some findings take their severity at run time)
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution
**CWE**: CWE-79
**D3FEND**: D3-IVA

## What it does

#14 (from nuclei) — headless-driven YAML templates.

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

## Request footprint

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Headless DOM templates skipped (passive mode) | No action. |
| info | Headless template '⟨name⟩' — browser launch failed | No action. |
| info | Headless templates skipped (Playwright not installed) | No action. |
| info | Headless templates skipped (PyYAML not installed) | No action. |
| info | Headless templates — none found | No action. |
| varies | [headless template] ⟨name⟩ | — |

## Evidence the check records

- Headless DOM templates skipped (passive mode): Pass --aggressive to drive a real browser against the target.
- Headless templates skipped (Playwright not installed): Install: `pip install playwright && playwright install chromium`.
- Headless templates skipped (PyYAML not installed): Install pyyaml to enable.
- Headless templates — none found: No template in ~/.wpsecscan/templates/ includes a `headless:` block.
- Headless template '⟨name⟩' — browser launch failed: Playwright couldn't launch chromium (run `playwright install chromium`).
- [headless template] ⟨name⟩: Headless template ⟨value⟩ matched against the rendered DOM.

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
wpsecscan only headless_templates https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
