---
id: a11y_lite
title: "Accessibility smoke check"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 118
---

# Accessibility smoke check

**check_id**: `a11y_lite`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: low
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

Lightweight accessibility (a11y) smoke check.

NOT a replacement for axe-core or Lighthouse — just a quick "is this site
missing the basics" check. Three rules:
  1. &lt;html&gt; must have lang=
  2. All &lt;img&gt; on the homepage must have alt= (empty alt is OK; missing isn't)
  3. The page must have a &lt;title&gt;

Why ship this? ADA Title III (US) and EU EAA (June 2025) increasingly turn
basic a11y misses into legal liability. Scanner users who run wpsecscan on
their own sites benefit from a heads-up.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | a11y smoke check flagged ⟨count⟩ basic issue(s) | These are the lowest bar of accessibility. Run a full audit (Lighthouse, axe DevTools, pa11y) for WCAG 2.1 AA conformance — increasingly required by ADA Title III (US) and the EU European Accessibility Act (from June 2025). |
| info | a11y check skipped — / didn't return HTML | No action. |
| info | a11y smoke check passed (homepage) | No action from this smoke check, but run a real audit (Lighthouse, axe DevTools, or pa11y) for WCAG 2.1 AA compliance. |

## Evidence the check records

- a11y check skipped — / didn't return HTML: GET / returned no body.
- a11y smoke check passed (homepage): &lt;html lang=&gt; ✓ · ⟨count⟩ images all have alt= ✓ · &lt;title&gt; ✓

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: n/a
- **compliance_map / iso_27001**: n/a

## Run only this check

```
wpsecscan only a11y_lite https://example.com
```

`only` runs this check alone and prints its findings.
