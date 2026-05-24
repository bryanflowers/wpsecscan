# HTTP/2 CRLF smuggling probe (#24)

**check_id**: `http2_smuggling`
**aggressive**: yes
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-444
**D3FEND**: D3-NTA

## What it does

#24 + #25 — HTTP/2 + HTTP/3 CRLF / desync probes.

#24: send HTTP/2 requests with CRLF in header values; flag if the server
     accepts them (proves no proper H2 header validation).
#25: HTTP/3 desync — best-effort with httpx h2 fallback since aioquic
     isn't a hard dep.

Aggressive only.

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
wpsecscan --target https://example.com --only http2_smuggling
```
