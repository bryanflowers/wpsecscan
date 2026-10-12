---
id: header_smuggling_case
title: "Header smuggling via case sensitivity"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "Transport & headers"
words: 195
---

# Header smuggling via case sensitivity

**check_id**: `header_smuggling_case`
**aggressive**: yes
**category**: Transport & headers
**max severity**: medium
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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Header case-sensitivity differential — ⟨count⟩ variant(s) changed response | Use a normalising proxy (nginx, HAProxy, Envoy) that rejects duplicate critical headers (Content-Length, Transfer-Encoding) outright with 400 Bad Request. nginx does this by default; if you're terminating TLS in app code, you've likely got a custom parser worth auditing. |
| info | Header case-sensitivity probe — no differential observed | No action. |
| info | Header smuggling case-sensitivity probe skipped (passive mode) | No action. |
| info | Header smuggling probe — baseline / unreachable | No action. |

## Evidence the check records

- Header smuggling case-sensitivity probe skipped (passive mode): Pass --aggressive to enable.
- Header smuggling probe — baseline / unreachable: Couldn't fetch / to baseline.
- Header case-sensitivity differential — ⟨count⟩ variant(s) changed response: ⟨value⟩ When a proxy and the backend disagree about how to handle duplicate or case-variant headers, that disagreement IS the request-smuggling precondition. Worth pairing with the smuggling_probe check for active CL.TE/TE.CL confirmation.
- Header case-sensitivity probe — no differential observed: Probed ⟨count⟩ header variants; none caused a meaningful response change.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## References

- primary: https://portswigger.net/research/http-desync-attacks

## Run only this check

```
wpsecscan only header_smuggling_case https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
