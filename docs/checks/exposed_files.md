---
id: exposed_files
title: "Exposed files"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "File & directory exposure"
words: 147
---

# Exposed files

**check_id**: `exposed_files`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Exposed sensitive-file check.

Reads the probe list in data/known_paths.txt, where each entry is
path|severity|label, then GETs every path. A 200 response is reported with
the severity and label from the list (the list spans critical to info), for
example backups, SQL dumps, .env and VCS files. To avoid false positives on
sites that answer 200 for every URL, it first fetches / and discards
HTML responses that match the homepage, or that come from paths whose real
content is never HTML. If the list is missing an info finding says so. Fix:
delete the file or deny it at the server, and rotate any credentials it held.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low, info) | Exposed: ⟨label⟩ at /⟨path⟩ | Remove /⟨path⟩ from the document root immediately, or add a server-level deny rule. For backups/secrets, also rotate any credentials they contained — assume they are compromised. |
| info | Exposed-files probe list missing | Rebuild the scanner — the data file did not ship with the binary. |
| info | No high-risk exposed files found | No action needed. |

## Evidence the check records

- Exposed-files probe list missing: known_paths.txt not found in bundle.
- Exposed: ⟨label⟩ at /⟨path⟩: GET /⟨path⟩ → 200 (⟨value⟩) preview: ⟨snippet⟩
- No high-risk exposed files found: Probed ⟨count⟩ known-bad paths; none returned 200.

## Suggested fix

Block common backup/source-leak paths (Nginx). Where to apply it: nginx server block.

```nginx
location ~* \.(bak|swp|sql|env|gitconfig|gitignore)$ { deny all; }
location ~ /\.git { deny all; }
location = /wp-config.php { deny all; }
location = /readme.html { deny all; }
location = /xmlrpc.php { deny all; }
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/wp-config.php.bak
curl -sI https://example.com/.env
curl -sI https://example.com/.git/config
curl -sI https://example.com/wp-content/debug.log
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.20
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only exposed_files https://example.com
```

`only` runs this check alone and prints its findings.
