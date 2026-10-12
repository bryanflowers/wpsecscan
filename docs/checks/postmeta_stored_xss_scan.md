---
id: postmeta_stored_xss_scan
title: "post_meta stored-XSS scan via REST (#54)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 75
---

# post_meta stored-XSS scan via REST (#54)

**check_id**: `postmeta_stored_xss_scan`
**aggressive**: no
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-79
**D3FEND**: D3-OE

## What it does

Stored-XSS scan of post_meta exposed via REST.

Round-64 #54 — many plugins write attacker-controllable data into
post_meta and then expose it via /wp-json/wp/v2/posts?_embed=true. If
the value is rendered HTML, the resulting field appears intact. We pull
the most recent N posts, walk their `.meta` field, and flag any value
that contains an unescaped &lt;script&gt; tag (the canonical "this is
stored-XSS in the wild" signal).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Stored-XSS-shaped content in post_meta (⟨count⟩ match) | Either: (a) These are LIVE stored-XSS payloads from a compromised input — view the affected posts in an isolated browser, remove the payload, and audit how it landed there. (b) A plugin is legitimately storing HTML in meta and exposing it to the world (rare and bad). Hide the meta from REST via `register_meta(..., 'show_in_rest' => false)`. |

## Evidence the check records

- Stored-XSS-shaped content in post_meta (⟨count⟩ match): Matches (first 5): ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only postmeta_stored_xss_scan https://example.com
```

`only` runs this check alone and prints its findings.
