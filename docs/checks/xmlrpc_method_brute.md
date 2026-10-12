---
id: xmlrpc_method_brute
title: "XML-RPC hidden-method brute-force (#8)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 149
---

# XML-RPC hidden-method brute-force (#8)

**check_id**: `xmlrpc_method_brute`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

#8 (from wpscan) — XML-RPC hidden-method brute-force.

`xmlrpc.php` lets plugins register custom methods alongside the WP-core
methods. `system.listMethods` usually returns them, but some plugins hide
methods from the listing while still exposing them. wpscan brute-forces
~200 method-name candidates to find these.

We send `<methodCall><methodName>X</methodName>...</methodCall>` for each
candidate name; a `faultCode -32601 "method does not exist"` means it
truly doesn't, any other response (auth required, malformed-params,
success) means the method IS registered.

Passive — single GET to confirm xmlrpc.php is enabled before brute-forcing.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | XML-RPC: ⟨count⟩ hidden method(s) registered | 1. If you don't use XML-RPC at all, disable it: nginx `location = /xmlrpc.php { deny all; }` (also blocks Jetpack — review trade-off). 2. If you need Jetpack but nothing else, use a plugin like 'Disable XML-RPC Pingback' or `add_filter('xmlrpc_methods', function($m){ unset($m['internal.X']); return $m; })` to whitelist only the methods you genuinely need. |
| info | XML-RPC method brute-force skipped (xmlrpc.php not accessible) | No action. |
| info | XML-RPC method brute-force — no hidden methods found | No action. |

## Evidence the check records

- XML-RPC: ⟨count⟩ hidden method(s) registered: ⟨value⟩ These methods don't appear in `system.listMethods` but accept XML-RPC calls. If any are exec-style (`debug.eval`, `internal.shell`, `updraftplus.dumpConfig`), they're worth deeper manual review with appropriate parameters.
- XML-RPC method brute-force skipped (xmlrpc.php not accessible): GET /xmlrpc.php returned ⟨value⟩.
- XML-RPC method brute-force — no hidden methods found: Probed ⟨count⟩ candidate method names; only the WP-core baseline (⟨count⟩ method(s)) responded as registered.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only xmlrpc_method_brute https://example.com
```

`only` runs this check alone and prints its findings.
