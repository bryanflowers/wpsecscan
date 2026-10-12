---
id: xmlrpc_amplification
title: "xmlrpc.php multicall amplification ratio"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Other"
words: 114
---

# xmlrpc.php multicall amplification ratio

**check_id**: `xmlrpc_amplification`
**aggressive**: no
**category**: Other
**max severity**: high
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1498.001 — Network DoS: Direct

## What it does

Measure xmlrpc.php system.multicall response amplification.

Existing xmlrpc_deep flags multicall availability. This one quantifies it:
one POST with 50 nested wp.getUsersBlogs calls. Compute the
response-bytes / request-bytes ratio. &gt;100x = high (concrete DoS math).

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low | xmlrpc.php system.multicall amplifies ⟨ratio⟩x (50-call batch) | 1. Disable XML-RPC entirely if you don't use the Jetpack mobile-app or remote-publishing workflows. In wp-config.php: add_filter('xmlrpc_enabled', '__return_false'); 2. If XML-RPC must stay, disable system.multicall specifically: add_filter('xmlrpc_methods', function($m) { unset($m['system.multicall']); return $m; }); 3. Block /xmlrpc.php at the web server when feasible — `nginx: location = /xmlrpc.php { deny all; }`. |

## Evidence the check records

- xmlrpc.php system.multicall amplifies ⟨ratio⟩x (50-call batch): POST /xmlrpc.php (50 wp.getUsersBlogs calls, ⟨req_bytes⟩ bytes) → ⟨resp_bytes⟩ bytes response. Amplification factor: ⟨ratio⟩x. Each multicall request packs N method invocations into one HTTP request; the server returns N response bodies back. Even with auth errors, each method generates a verbose fault structure. Concrete attack math: at ⟨ratio⟩x amplification, an attacker with 1 Mbit/s upload can deliver up to ⟨ratio⟩ Mbit/s of response bandwidth to your server's outbound interface — a cheap bandwidth-bill DoS.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: SC.L2-3.13.4
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 12.1
- **compliance_v2 / iso_27001_2022**: A.8.6

## Run only this check

```
wpsecscan only xmlrpc_amplification https://example.com
```

`only` runs this check alone and prints its findings.
