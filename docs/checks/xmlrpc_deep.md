---
id: xmlrpc_deep
title: "XML-RPC method enumeration"
severity_max: high
severity_dynamic: true
aggressive: false
category: "GraphQL & APIs"
words: 136
---

# XML-RPC method enumeration

**check_id**: `xmlrpc_deep`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high (some findings take their severity at run time)
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.004 — Brute Force: Credential Stuffing

## What it does

Deep XML-RPC enumeration.

Beyond what login.py already checks, this:
  1. Lists every registered XML-RPC method via system.listMethods
  2. Flags dangerous combinations (pingback.ping + system.multicall = SSRF amplifier)
  3. Probes for the Akismet pingback validation bug pattern (CVE-2014 family)
  4. Checks if mt.supportedMethods / blogger.* endpoints are open (legacy editor protocols)

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | XML-RPC brute-force amplifier present: multicall + wp.getUsersBlogs | Disable at minimum system.multicall: add_filter('xmlrpc_methods', function($m){ unset($m['system.multicall']); return $m; }); Or fully block /xmlrpc.php at the server. |
| varies (high, medium, info) | XML-RPC method exposed: ⟨method⟩ | Disable this specific method: add_filter('xmlrpc_methods', function($m){ unset($m['⟨method⟩']); return $m; }); |
| info | XML-RPC endpoint not responding to system.listMethods | Likely good — either XML-RPC is blocked or never was enabled. No action needed. |
| info | XML-RPC enumerated: ⟨count⟩ method(s) | If you don't use Jetpack / WP mobile / pingbacks, disable XML-RPC entirely: add_filter('xmlrpc_enabled', '__return_false'); Or block /xmlrpc.php at the web server. |
| info | XML-RPC responds but no methods enumerated | No action needed. |

## Evidence the check records

- XML-RPC enumerated: ⟨count⟩ method(s): Sample (first 30): ⟨value⟩ ...
- XML-RPC endpoint not responding to system.listMethods: POST /xmlrpc.php -&gt; ⟨value⟩
- XML-RPC responds but no methods enumerated: system.listMethods returned 200 but the response body contained no &lt;string&gt; entries.
- XML-RPC brute-force amplifier present: multicall + wp.getUsersBlogs: Both system.multicall and wp.getUsersBlogs are exposed. Attackers wrap dozens of auth attempts in a single HTTP request (multicall) to bypass per-IP rate-limit that only sees one request per http hit.
- XML-RPC method exposed: ⟨method⟩: system.listMethods includes ⟨method⟩. ⟨reason⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only xmlrpc_deep https://example.com
```

`only` runs this check alone and prints its findings.
