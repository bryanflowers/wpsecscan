# DNS deep — DNSSEC/CAA/TXT-secret/DoH/PTR/wildcard (#32-39)

**check_id**: `dns_deep`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1071.004 — Application Layer Protocol: DNS
**CWE**: CWE-693
**D3FEND**: D3-DNSTI

## What it does

Round-59 #32-39 — DNS deep-dive audit.

#32 DNSSEC — RRSIG/DNSKEY presence
#33 CAA — `CAA 0 issue "..."` records (cert-issuance control)
#34 TXT secret scan — look for accidentally-published API keys / tokens
#35 DoH — does the apex publish a SVCB/HTTPS record advertising DoH?
#36 Resolver fingerprint — what resolver answers? (Cloudflare / Google /
   on-prem)
#37 Glue records — apex NS pointing to in-bailiwick records present?
   (presence = good, absence = lame delegation risk)
#38 Wildcard — does `*-nonexistent-abcdef.apex` resolve? indicates
   wildcard A/CNAME (info-leak + brand-impersonation risk)
#39 PTR — does the apex IP reverse-resolve to the apex? mismatch is
   common but worth flagging

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-20
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-20
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.f
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 4.9
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only dns_deep
```
