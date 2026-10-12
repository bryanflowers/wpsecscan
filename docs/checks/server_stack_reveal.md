---
id: server_stack_reveal
title: "Server-stack reveal + PHP EOL detect (#B22+B29)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 92
---

# Server-stack reveal + PHP EOL detect (#B22+B29)

**check_id**: `server_stack_reveal`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Round-62 #B22, #B29 — server-side stack reveal + PHP version detect.

Parses every banner-style header WordPress + nginx/Apache + PHP-FPM commonly
leak, then maps versions against EOL data to flag end-of-life software.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Apache ⟨v⟩ is end-of-life | Upgrade Apache to 2.4 (current stable). Apache 2.2 hit EOL in 2018. |
| high | PHP ⟨php_version⟩ is end-of-life | Upgrade PHP to a supported version (8.3 or later). Check https://www.php.net/supported-versions.php. |
| medium | nginx ⟨v⟩ is end-of-life | Upgrade nginx to a current stable version. |
| low | Server-stack reveal (⟨count⟩ banner header(s)) | Hide via: nginx: server_tokens off; proxy_hide_header X-Powered-By; more_clear_headers Server; Apache: ServerTokens Prod; ServerSignature Off; Header unset X-Powered-By; PHP: php_value expose_php Off (php.ini) |
| info | PHP ⟨php_version⟩ detected (supported) | No action. |
| info | Stack reveal — no headers returned | No action. |
| info | Stack reveal — no leaks, all software current | No action. |

## Evidence the check records

- Stack reveal — no leaks, all software current: No revealing banner headers.
- PHP ⟨php_version⟩ is end-of-life: X-Powered-By header reports PHP/⟨php_version⟩; PHP ⟨major_minor⟩ no longer receives security updates.
- nginx ⟨v⟩ is end-of-life: Server header reports nginx/⟨v⟩; major.minor ⟨mm⟩ no longer maintained.
- Apache ⟨v⟩ is end-of-life: Server header reports Apache/⟨v⟩; ⟨mm⟩ EOL.
- PHP ⟨php_version⟩ detected (supported): PHP/⟨php_version⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: SI-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: CM.L2-3.4.6
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## References

- https://www.php.net/supported-versions.php

## Run only this check

```
wpsecscan only server_stack_reveal https://example.com
```

`only` runs this check alone and prints its findings.
