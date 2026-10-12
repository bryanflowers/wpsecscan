---
id: xss_reflected
title: "Reflected XSS probes"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 113
---

# Reflected XSS probes

**check_id**: `xss_reflected`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

Reflected XSS probes — uses a benign marker payload with a per-scan nonce.

Does not execute any JavaScript. Detection is purely structural: did our angle
brackets and quotes survive into the response unescaped?

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Reflected payload (angle brackets unescaped) in ⟨desc⟩ | Escape all user-controlled output with esc_html(), esc_attr(), or wp_kses() depending on context. For search query reflection specifically, use the_search_query(). Audit any plugin/theme rendering this parameter. |
| low | Parameter '⟨param⟩' is reflected (brackets escaped) | Ensure attribute values in PHP templates are wrapped with esc_attr(). |
| info | No reflected XSS markers detected on tested parameters | No action needed for the tested endpoints. |

## Evidence the check records

- No reflected XSS markers detected on tested parameters: Probed ⟨count⟩ parameters with a unique nonce payload; none reflected unescaped.
- Reflected payload (angle brackets unescaped) in ⟨desc⟩: GET /?⟨param⟩=⟨payload⟩ -&gt; ⟨value⟩ Marker ⟨marker_raw⟩ appears verbatim in response body. Unescaped &lt; and &gt; characters in HTML output are the precondition for reflected XSS.
- Parameter '⟨param⟩' is reflected (brackets escaped): Marker 'wpsx⟨nonce⟩' reflected; angle brackets appear escaped. Low risk on its own, but quote-context bugs can still enable attribute-break XSS.

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

- primary: https://owasp.org/www-community/attacks/xss/
- deep dive: https://portswigger.net/web-security/cross-site-scripting/reflected

## Run only this check

```
wpsecscan only xss_reflected https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
