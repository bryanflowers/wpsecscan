---
id: email_security_deep
title: "Email deep — DMARC/MTA-STS/BIMI/ARC/DKIM/SPF (#24-31)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 331
---

# Email deep — DMARC/MTA-STS/BIMI/ARC/DKIM/SPF (#24-31)

**check_id**: `email_security_deep`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566 — Phishing
**CWE**: CWE-290
**D3FEND**: D3-NTA

## What it does

Round-59 #24-31 — Email-security deep dive.

Existing `dns_security.py` covers basic SPF/DMARC/DKIM presence. This
module adds the deep checks:

#24 DMARC progression — flag p=none &gt; 30 days old as monitor-only stuck
#25 MTA-STS — _mta-sts.&lt;host&gt; TXT + /.well-known/mta-sts.txt policy
#26 BIMI — default._bimi.&lt;host&gt; TXT (brand indicator)
#27 ARC — outbound mail authentication chain (best-effort — we can only
   check headers if a sample mail is presented; for the scanner we just
   note absence of an arc-sealer header on the home-page response
   from any mail-related script)
#28 DKIM rotation — flag DKIM TXT records with a published rotation
   timestamp &gt;180 days (best-effort, only when DKIM record contains
   `t=`/`g=` selector metadata)
#29 SPF DNS-lookup count — RFC 7208 caps SPF at 10 includes; we walk
   and count
#30 SPF macros — flag macro usage (`%{...}`) which can reveal info
#31 Open-relay — short connect to MX on :25 and EHLO is NOT in scope
   (would require raw SMTP from the scanner host, often blocked by
   ISPs). Instead we emit guidance + a link to mxtoolbox.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | SPF for ⟨apex⟩ exceeds RFC 7208 10-lookup limit | Over-10 SPF causes PermError → DMARC fails → mail rejected by strict receivers. Flatten includes (services like SPF-Manager, MxToolbox SPF Optimizer) or consolidate senders. |
| medium | SPF for ⟨apex⟩ approaching 10-lookup limit (⟨cnt⟩) | Plan a flatten before you exceed 10 — every new include risks PermError. |
| medium | SPF record uses macros | SPF macros like %{i} / %{s} expand to sender IP / address. They can be abused to fingerprint your infra. Replace with static includes if possible. |
| low | DKIM selector '⟨sel⟩' in testing mode (t=y) | Remove t=y once DKIM is verified. Receivers may down-weight test-mode signatures. |
| low | DMARC policy stuck on p=none (monitor-only) | p=none is fine for the first 2-4 weeks. After clean RUA reports, move to p=quarantine, then p=reject. Track rua= reports with Postmark/dmarcian/Valimail. |
| low | No MTA-STS policy for ⟨apex⟩ | MTA-STS forces TLS on inbound MX. Publish: TXT _mta-sts.⟨apex⟩ "v=STSv1; id=20260101000000Z" https://mta-sts.⟨apex⟩/.well-known/mta-sts.txt with `version: STSv1\nmode: enforce\nmx: ...` |
| info | ARC (Authenticated Received Chain) — manual verification required | If you forward mail through a mailing-list or relay, enable ARC at the relay so downstream DMARC checks survive the hop. |
| info | BIMI eligible but not configured | Generate an SVG-Tiny-1.2 logo + (paid) Verified-Mark-Certificate from Entrust/DigiCert. Publish default._bimi.&lt;apex&gt; TXT with `v=BIMI1; l=<logo-url>; a=<vmc-url>`. |
| info | BIMI record published for ⟨apex⟩ | No action — BIMI helps brand recognition in inbox preview. |
| info | Email-deep audit — all checks clean | No action. |
| info | Email-deep skipped (IP/localhost) | No action. |
| info | MTA-STS published in testing mode | After verifying no legitimate sender breaks, switch mode to `enforce`. |
| info | Open-relay test — use mxtoolbox | Use mxtoolbox to confirm no MX of ⟨apex⟩ accepts foreign-to-foreign mail. |

## Evidence the check records

- ARC (Authenticated Received Chain) — manual verification required: ARC headers can only be checked on actual delivered mail. Send a test mail to a Gmail account and inspect the raw source for ARC-Seal/ARC-Message-Signature.
- Open-relay test — use mxtoolbox: Outbound :25 from this scanner is usually blocked. Test from mxtoolbox: https://mxtoolbox.com/diagnostic.aspx
- Email-deep skipped (IP/localhost): host=⟨host⟩
- DMARC policy stuck on p=none (monitor-only): _dmarc.⟨apex⟩ = ⟨dmarc⟩
- No MTA-STS policy for ⟨apex⟩: No _mta-sts TXT and no /.well-known/mta-sts.txt on mta-sts.&lt;apex&gt;.
- BIMI record published for ⟨apex⟩: default._bimi.⟨apex⟩ TXT present.
- MTA-STS published in testing mode: mode: testing — not enforcing.
- BIMI eligible but not configured: DMARC at quarantine/reject means ⟨apex⟩ is BIMI-eligible. No default._bimi TXT.
- SPF for ⟨apex⟩ exceeds RFC 7208 10-lookup limit: Counted ~⟨cnt⟩ lookup-causing mechanisms in `⟨value⟩`.
- SPF record uses macros: SPF: ⟨value⟩
- DKIM selector '⟨sel⟩' in testing mode (t=y): ⟨sel⟩._domainkey.⟨apex⟩: ⟨value⟩
- SPF for ⟨apex⟩ approaching 10-lookup limit (⟨cnt⟩): `⟨value⟩`

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

## References

- https://mta-sts
- https://mxtoolbox.com/diagnostic.aspx
- https://mxtoolbox.com/diagnostic.aspx?type=2&q=

## Run only this check

```
wpsecscan only email_security_deep https://example.com
```

`only` runs this check alone and prints its findings.
