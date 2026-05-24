# DOM-XSS source/sink scan

**check_id**: `xss_dom_sinks`
**aggressive**: no
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

DOM-XSS sink detection in inline JavaScript.

Scans page HTML for inline `<script>` blocks and looks for dangerous DOM
sinks paired with attacker-controllable sources (location, document.URL,
document.referrer, postMessage event.data).

Pure heuristic — false positives are common in WP because plugins inject
lots of inline JS. Confidence is set to "low" for raw matches; "medium"
when source+sink combo is in the same script block.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only xss_dom_sinks
```
