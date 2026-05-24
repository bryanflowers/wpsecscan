# Headless DOM templates (Playwright) (#14)

**check_id**: `headless_templates`
**aggressive**: yes
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
wpsecscan --target https://example.com --only headless_templates
```
