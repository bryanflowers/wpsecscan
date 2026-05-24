# Membership + LMS plugin audit (#4-5)

**check_id**: `wp_membership_lms_audit`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-285
**D3FEND**: D3-RAC

## What it does

Round-59 #4-5 — Membership + LMS plugin audit.

#4 Membership: MemberPress, Paid Memberships Pro, Restrict Content Pro.
   Payment + access-control glue — historically the source of capability
   bypass and price-tampering CVEs.
#5 LMS: LearnDash, LifterLMS, TutorLMS, Sensei. Quiz-bypass, completion
   spoofing, certificate-IDOR are the big themes.

Each plugin's REST endpoints + protected-content paths are probed for
unauthenticated readability — the most common bug class.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only wp_membership_lms_audit
```
