# HTTP request-smuggling indicators

**check_id**: `smuggling_probe`
**aggressive**: no
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

HTTP request-smuggling probe (passive — never actually smuggles).

A *real* smuggling test would send conflicting Content-Length / Transfer-Encoding
headers and observe whether the backend desyncs (a write-side action). We won't
do that — instead we PASSIVELY look for indicators that the front-end and back-end
disagree on framing:
  1. Detect HTTP/2 frontend with HTTP/1.1 backend (the highest-risk topology)
  2. Detect duplicate Host / Content-Length headers in the response (signs of
     a misconfigured reverse proxy that may also accept duplicates inbound)
  3. Detect a `Transfer-Encoding: chunked` echo / pass-through on a response
     to a HEAD request (front-end mishandles)

If any indicators are present, flag the risk class with a "verify with Burp /
smuggler.py" remediation — we deliberately stop short of confirming actively.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only smuggling_probe
```
