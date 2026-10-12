---
id: interactivity_api_state_leak
title: "Interactivity-API hydration state PII leak (A6)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 124
---

# Interactivity-API hydration state PII leak (A6)

**check_id**: `interactivity_api_state_leak`
**aggressive**: no
**category**: Injection & client-side
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1005 — Data from Local System
**CWE**: CWE-200
**D3FEND**: D3-FA

## What it does

A6 (v2.6.0) — Interactivity-API state leak.

WP 6.5+ ships the `@wordpress/interactivity` runtime: blocks declare
client-side state and actions via `data-wp-context`, `data-wp-bind`,
`data-wp-on`, etc. directives. The full server state often gets
serialised into the page's `&lt;script type="application/json"
id="wp-interactivity-data"&gt;` blob so the runtime can hydrate it.

Two patterns leak server state:

  • `data-wp-context='{"user_email":"foo@bar.com",…}'` on an element
    rendered by a personalisation plugin.
  • The wp-interactivity-data JSON blob containing user IDs, internal
    URLs, or feature-flag names.

Passive: scan the homepage for inline JSON state and flag any
high-signal keys (`email`, `phone`, `address`, `ssn`, `api_key`).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Interactivity API context leaks PII-shaped keys | Move the leaked fields out of data-wp-context (server-rendered into the HTML) into a separate authenticated /wp-json/ endpoint the runtime fetches AFTER login. The Interactivity runtime should only hold non-PII state in the client-visible JSON. |
| high | Interactivity-API hydration blob leaks PII-shaped keys | Audit which plugins push state into wp_initial_state(). For per-user data, fetch it via an authenticated REST request after the page loads rather than embedding into HTML. Run `wp interactivity-config audit` if WP-CLI extension exists. |

## Evidence the check records

- Interactivity API context leaks PII-shaped keys: data-wp-context blob contains keys: ⟨value⟩ Excerpt: ⟨value⟩
- Interactivity-API hydration blob leaks PII-shaped keys: &lt;script id='wp-interactivity-data'&gt; contains keys: ⟨value⟩ Blob size: ⟨count⟩ bytes First 300 bytes: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.3.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only interactivity_api_state_leak https://example.com
```

`only` runs this check alone and prints its findings.
