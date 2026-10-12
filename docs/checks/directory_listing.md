---
id: directory_listing
title: "Directory listing"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 118
---

# Directory listing

**check_id**: `directory_listing`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Directory-listing check.

Requests five WordPress directories with GET: /wp-content/uploads/,
/wp-content/plugins/, /wp-content/themes/, /wp-includes/ and /wp-content/.
A directory is reported (high) when it answers 200 and the body contains an
"Index of" title or heading, or "Directory listing for". Each exposed path is
its own finding. If none of the five lists its contents, one info finding is
emitted. Fix: add `Options -Indexes` to .htaccess on Apache, make sure
`autoindex` is off on Nginx, and optionally place an empty index.html in the
directory. Five GET requests, no authentication.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Directory listing enabled at /⟨p⟩ | Disable directory listing. Apache: add `Options -Indexes` to .htaccess. Nginx: ensure `autoindex` is off (default). Place an empty index.html in /⟨p⟩ as belt-and-braces. |
| info | No directory listings detected | No action needed. |

## Evidence the check records

- No directory listings detected: Probed ⟨count⟩ WP directories; none expose an index page.
- Directory listing enabled at /⟨p⟩: GET /⟨p⟩ → 200 with apache-style 'Index of' page.

## Suggested fix

Disable directory listing. Where to apply it: .htaccess (root).

```apache
Options -Indexes
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/wp-content/uploads/ | grep -i 'index of'
curl -s https://example.com/wp-content/plugins/ | grep -i 'index of'
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L1-3.1.20
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only directory_listing https://example.com
```

`only` runs this check alone and prints its findings.
