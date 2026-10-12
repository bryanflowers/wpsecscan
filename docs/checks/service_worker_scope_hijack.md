---
id: service_worker_scope_hijack
title: "Service-worker origin-wide scope (A29)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 138
---

# Service-worker origin-wide scope (A29)

**check_id**: `service_worker_scope_hijack`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1554 — Compromise Client Software Binary
**CWE**: CWE-1188
**D3FEND**: D3-FA

## What it does

A29 (v2.6.0) — service-worker scope-hijack risk.

A service worker registered with `scope: "/"` intercepts navigation
requests for the entire origin. When a plugin folder ships a SW with
scope "/", that PLUGIN gains the ability to MITM every page on the
site (modify HTML, inject scripts, exfil cookies via fetch handlers).
If the plugin is later compromised, it has total client-side control.

Passive: GET /sw.js + /service-worker.js + the canonical PWA paths,
look at the `Service-Worker-Allowed` response header or the SW's
own `self.registration.scope` reference; flag medium when the SW
registered from a non-root URL takes scope "/".

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Plugin-shipped service worker claims origin-wide scope: ⟨path⟩ | 1. Restrict the SW's scope to its own folder by NOT sending the Service-Worker-Allowed: / header. 2. If a root-scope SW is required for the PWA install, move it to the web root (/sw.js) so its provenance matches the operator's expectations. 3. Pin the SW's source to a specific git SHA in the plugin update policy. |

## Evidence the check records

- Plugin-shipped service worker claims origin-wide scope: ⟨path⟩: GET ⟨path⟩ returns 200. Service-Worker-Allowed header: ⟨allowed⟩ SW body references root scope. If this plugin is later compromised (supply-chain or local code-tamper), it can MITM every page on the origin via fetch handler.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-18
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only service_worker_scope_hijack https://example.com
```

`only` runs this check alone and prints its findings.
