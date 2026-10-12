---
id: block_bindings_exposure
title: "Gutenberg Block-Bindings custom-source audit (A5)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 163
---

# Gutenberg Block-Bindings custom-source audit (A5)

**check_id**: `block_bindings_exposure`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

A5 (v2.6.0) — Gutenberg Block-Bindings exposure.

Gutenberg 6.5+ added the Block Bindings API: a block attribute can be
bound to a PHP source (post meta, post property, custom callback) via
the `metadata.bindings` field in block markup. The default sources
are `core/post-meta` and `core/pattern-overrides`; plugins register
their own sources via `register_block_bindings_source()`.

Two known bug classes:

  • A custom bindings-source callback that reads a meta key but
    doesn't restrict by post type can leak private-post meta to the
    public frontend.
  • A bindings source registered without `uses_context` validation
    can be invoked from contexts the developer didn't anticipate.

Passive: scan the rendered HTML for `metadata.bindings` references +
serialised block markup containing `&lt;!-- wp:` ... `metadata":{
"bindings":{` patterns. Flag any custom (non-core) source name as
"audit required".

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Custom Block-Bindings sources in use: ⟨value⟩ | 1. For each listed source, locate the plugin's register_block_bindings_source() call. 2. Verify the source's `get_value_callback` checks the post type and the current user's capability before returning the value. 3. If the callback reads from post meta, restrict to whitelisted meta keys — never pass user-supplied key names through. 4. Add 'uses_context' =&gt; [...] so the source only runs in the block contexts the developer intended. |

## Evidence the check records

- Custom Block-Bindings sources in use: ⟨value⟩: Rendered HTML contains Block-Bindings references to non-core sources: ⟨value⟩ Custom bindings-source callbacks have leaked private post meta to the public frontend when the registration didn't validate post type or capability. Manual audit required.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only block_bindings_exposure https://example.com
```

`only` runs this check alone and prints its findings.
