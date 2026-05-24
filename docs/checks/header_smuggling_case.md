# Header smuggling via case sensitivity

**check_id**: `header_smuggling_case`
**aggressive**: yes
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-444
**D3FEND**: D3-NTA

## What it does

H10 Header smuggling via case sensitivity / duplication.

HTTP says header names are case-insensitive. In practice, some proxies fold
duplicates by joining values, others by picking the first, others by picking
the last. A request like:

    Content-Length: 11
    content-length: 4
    Body: x=1&y=22

results in front-end / back-end disagreeing on where the request ends, which
is the desync precondition.

We send a few crafted requests with case-variant or duplicate headers and
watch for asymmetric behaviour (status code or body length differs from the
baseline). This is much narrower than the full smuggling_probe check — it
only catches the case-normalisation class of disagreement.

Aggressive only — sending non-conformant headers may trip WAF rules.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only header_smuggling_case
```
