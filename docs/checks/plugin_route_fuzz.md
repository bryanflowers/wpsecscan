---
id: plugin_route_fuzz
title: "Plugin REST-route fuzzer"
severity_max: high
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 118
---

# Plugin REST-route fuzzer

**check_id**: `plugin_route_fuzz`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-RAC

## What it does

H9 Plugin-route fuzzer.

Extends the existing plugin enumeration: for every detected plugin slug,
probe its known unauthenticated REST endpoints (sourced from a curated
mapping). Catches the long tail of "this plugin exposes /wp-json/foo/v1/
without an auth check" — about 30% of WordPress sites run at least one.

We're conservative: only GET probes (no writes), only `info` severity for
"endpoint accessible" findings; the severity bumps to `medium`/`high` if
the response body matches a known data-leak signature.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Unauthenticated plugin endpoints leaking data — ⟨count⟩ confirmed | These REST endpoints respond to unauthenticated requests with structured data that matches the plugin's data shape. Audit the plugin's `register_rest_route` definitions — every route should declare a `permission_callback`. Default-deny: `'permission_callback' => function() { return current_user_can('read'); }`. |
| medium | ⟨count⟩ plugin endpoint(s) accessible unauthenticated (no data leak signature) | Endpoints respond 2xx unauthenticated. Whether that's intentional depends on the plugin's design — confirm by reading the plugin's REST route definitions. Add a `permission_callback` to enforce authentication if not intended. |
| info | Plugin-route fuzzer skipped (no plugins detected) | No action. |
| info | Plugin-route fuzzer — none of the ⟨count⟩ detected plugin(s) has known routes | No action. |

## Evidence the check records

- Plugin-route fuzzer skipped (no plugins detected): The plugins check didn't enumerate any plugin slugs to probe.
- Plugin-route fuzzer — none of the ⟨count⟩ detected plugin(s) has known routes: The detected plugins aren't in our curated mapping. Add custom signatures via ~/.wpsecscan/signatures/.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only plugin_route_fuzz https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
