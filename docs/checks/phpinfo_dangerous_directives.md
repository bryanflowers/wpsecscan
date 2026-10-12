---
id: phpinfo_dangerous_directives
title: "phpinfo() dangerous-runtime-flag audit"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "File & directory exposure"
words: 68
---

# phpinfo() dangerous-runtime-flag audit

**check_id**: `phpinfo_dangerous_directives`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Gather Victim Host: Client Configurations

## What it does

When phpinfo() output is exposed, parse it for dangerous runtime flags.

The existing `exposed_files` check flags `phpinfo.php` / `info.php`
exposure. This check goes one step further: download the page and parse
the rendered phpinfo() table for dangerous `allow_url_include=On`,
`allow_url_fopen=On`, `display_errors=On`, and `expose_php=On` settings.
Each merits a separate finding because the remediation is different.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, medium, low) | phpinfo exposes `⟨key⟩ = ⟨v⟩` — ⟨value⟩ | In php.ini (or .user.ini), set `⟨key⟩ = Off`. Then verify with `php -i \| grep ⟨key⟩` or by reloading the (still-exposed) phpinfo page. After fixing, ALSO delete ⟨found_path⟩ from the web root — leaving phpinfo public is itself a finding. |

## Evidence the check records

- phpinfo exposes `⟨key⟩ = ⟨v⟩` — ⟨value⟩: Parsed from ⟨found_path⟩: ⟨key⟩ = ⟨v⟩ ⟨what⟩

## Compliance mapping

- **compliance_map / pci_dss**: 2.2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: CM.L2-3.4.7
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 4.8
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan only phpinfo_dangerous_directives https://example.com
```

`only` runs this check alone and prints its findings.
