---
id: xss_dom_sinks
title: "DOM-XSS source/sink scan"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 126
---

# DOM-XSS source/sink scan

**check_id**: `xss_dom_sinks`
**aggressive**: no
**category**: Injection & client-side
**max severity**: medium
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Inline script pairs DOM source + sink in ⟨value⟩ | Audit the inline script. Replace string-based sinks (innerHTML, document.write) with textContent / createElement. If reading location.* / document.referrer, sanitize via DOMPurify or an explicit allowlist before injecting. |
| info | No source-sink combinations found in inline scripts | No action needed for this check (false-negatives possible — bundled JS isn't analyzed). |

## Evidence the check records

- No source-sink combinations found in inline scripts: Scanned ⟨count⟩ pages; no inline &lt;script&gt; block paired a tainted source with a dangerous sink.
- Inline script pairs DOM source + sink in ⟨value⟩: Sources detected: ⟨value⟩ Sinks detected: ⟨value⟩ Script snippet: ⟨value⟩ This is a *candidate* — confirm by reading the full handler. Inline JS that does e.g. `document.write(location.hash)` is a textbook DOM-XSS hit.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
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
wpsecscan only xss_dom_sinks https://example.com
```

`only` runs this check alone and prints its findings.
