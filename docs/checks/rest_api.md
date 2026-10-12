---
id: rest_api
title: "WP REST API surface audit"
severity_max: high
severity_dynamic: true
aggressive: false
category: "Discovery & enumeration"
words: 72
---

# WP REST API surface audit

**check_id**: `rest_api`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high (some findings take their severity at run time)
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WordPress REST API surface audit.

Probes /wp-json/ and common REST endpoints beyond /users (which the existing
users check covers). Flags exposed data the site owner may not realize is
publicly readable.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (high, medium, low, info) | Public REST endpoint exposes data: ⟨path⟩ | If you don't need this endpoint publicly, restrict it via the rest_endpoints filter: add_filter('rest_endpoints', function($e) { unset($e['⟨value⟩']); return $e; }); |
| info | No REST API surface findings | No action needed. |
| info | WordPress REST API exposes ⟨count⟩ namespace(s) | REST namespaces aren't sensitive by themselves but they reveal active plugins. Each namespace can be locked down via the rest_endpoints filter if exposure is unwanted. |

## Evidence the check records

- WordPress REST API exposes ⟨count⟩ namespace(s): Namespaces: ⟨value⟩
- Public REST endpoint exposes data: ⟨path⟩: GET ⟨path⟩ -&gt; 200 with expected content marker present. Endpoint description: ⟨desc⟩
- No REST API surface findings: Probed ⟨count⟩ endpoints; none returned exposed data.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/wp-json/ | jq '.namespaces'
curl -s https://example.com/wp-json/wp/v2/settings
# Restrict via rest_endpoints filter in functions.php
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L1-3.1.20
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only rest_api https://example.com
```

`only` runs this check alone and prints its findings.
