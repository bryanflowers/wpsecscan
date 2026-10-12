---
id: a11y_wcag_aaa
title: "WCAG 2.2 AAA-level accessibility extras (#99)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 129
---

# WCAG 2.2 AAA-level accessibility extras (#99)

**check_id**: `a11y_wcag_aaa`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-1004
**D3FEND**: D3-NTA

## What it does

WCAG 2.2 AAA-level accessibility extras.

Round-64 #99 — `a11y_deep.py` already covers WCAG 2.2 AA. This check
adds the small set of AAA criteria that can be remotely inferred:
  - 1.4.6 Contrast (Enhanced) — 7:1 for normal text, 4.5:1 for large
  - 2.3.2 Three Flashes (we flag any video tag without controls)
  - 2.4.10 Section Headings — minimum 1 &lt;h1&gt; per page
  - 3.1.5 Reading Level — flesch-kincaid-style heuristic

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WCAG 2.3.2 (AAA): autoplay &lt;video&gt; without controls | Add `controls` attribute + don't autoplay. Users with photosensitive epilepsy can't dismiss it otherwise. |
| low | WCAG 2.4.10 (AAA): no &lt;h1&gt; on homepage | Add exactly one &lt;h1&gt; per page describing the page's main topic. |
| info | Multiple &lt;h1&gt; elements (⟨h1_count⟩) — confusing for screen readers | Keep one &lt;h1&gt; per page; use &lt;h2&gt;+ for subsections. |
| info | WCAG 3.1.5 (AAA): reading level grade ⟨grade⟩ (above 9th grade) | Provide a simplified-text alternative for content above 9th-grade reading level. |

## Evidence the check records

- WCAG 2.4.10 (AAA): no &lt;h1&gt; on homepage: Found 0 &lt;h1&gt; elements on /
- WCAG 2.3.2 (AAA): autoplay &lt;video&gt; without controls: ⟨count⟩ autoplay video tag(s) without `controls` attribute
- Multiple &lt;h1&gt; elements (⟨h1_count⟩) — confusing for screen readers: Found ⟨h1_count⟩ &lt;h1&gt; elements
- WCAG 3.1.5 (AAA): reading level grade ⟨grade⟩ (above 9th grade): Flesch-Kincaid grade ⟨grade⟩ on homepage body text

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: n/a
- **compliance_map / iso_27001**: n/a

## Run only this check

```
wpsecscan only a11y_wcag_aaa https://example.com
```

`only` runs this check alone and prints its findings.
