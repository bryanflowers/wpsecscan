---
id: env_file_enum
title: ".env file exposure + secret sniffing (#67)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 90
---

# .env file exposure + secret sniffing (#67)

**check_id**: `env_file_enum`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-538
**D3FEND**: D3-FCR

## What it does

Probe + content-sniff for exposed .env files.

Round-64 #67 — Laravel/Symfony/Node-style .env files keep cropping up in
WordPress docroots (devs working alongside a Laravel API, or just bad
copy-paste habits). These files are usually pure secrets: DB creds,
AWS keys, Stripe keys, JWT secrets. We probe likely paths and, on hit,
scan the body for high-confidence secret patterns.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | .env file exposed at ⟨path⟩ | Block .env access publicly + ROTATE every secret in the file: Apache: &lt;FilesMatch "^\.env"&gt; Require all denied &lt;/FilesMatch&gt; Nginx: location ~ /\.env { deny all; return 404; } Move .env outside the docroot if possible (above public_html/). |
| critical | ⟨name⟩ leaked in ⟨path⟩ | ROTATE the leaked ⟨name⟩ immediately. Block .env publicly. Audit all secrets in the file. |

## Evidence the check records

- .env file exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes); KEY=VALUE pattern detected
- ⟨name⟩ leaked in ⟨path⟩: Pattern ⟨name⟩ matched in body of ⟨path⟩ (secret not printed for safety)

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only env_file_enum https://example.com
```

`only` runs this check alone and prints its findings.
