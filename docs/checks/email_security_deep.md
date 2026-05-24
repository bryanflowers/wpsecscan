# Email deep — DMARC/MTA-STS/BIMI/ARC/DKIM/SPF (#24-31)

**check_id**: `email_security_deep`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566 — Phishing
**CWE**: CWE-290
**D3FEND**: D3-NTA

## What it does

Round-59 #24-31 — Email-security deep dive.

Existing `dns_security.py` covers basic SPF/DMARC/DKIM presence. This
module adds the deep checks:

#24 DMARC progression — flag p=none > 30 days old as monitor-only stuck
#25 MTA-STS — _mta-sts.<host> TXT + /.well-known/mta-sts.txt policy
#26 BIMI — default._bimi.<host> TXT (brand indicator)
#27 ARC — outbound mail authentication chain (best-effort — we can only
   check headers if a sample mail is presented; for the scanner we just
   note absence of an arc-sealer header on the home-page response
   from any mail-related script)
#28 DKIM rotation — flag DKIM TXT records with a published rotation
   timestamp >180 days (best-effort, only when DKIM record contains
   `t=`/`g=` selector metadata)
#29 SPF DNS-lookup count — RFC 7208 caps SPF at 10 includes; we walk
   and count
#30 SPF macros — flag macro usage (`%{...}`) which can reveal info
#31 Open-relay — short connect to MX on :25 and EHLO is NOT in scope
   (would require raw SMTP from the scanner host, often blocked by
   ISPs). Instead we emit guidance + a link to mxtoolbox.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-8
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.f
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 9.7
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only email_security_deep
```
