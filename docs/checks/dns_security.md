---
id: dns_security
title: "DNS security (SPF/DMARC/DKIM)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 426
---

# DNS security (SPF/DMARC/DKIM)

**check_id**: `dns_security`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566.001 — Phishing: Spearphishing Attachment

## What it does

DNS-level security audit: SPF / DMARC / DKIM + WHOIS/RDAP domain expiry.

Uses the stdlib `socket` resolver via `asyncio.to_thread` so we don't pull
in `dnspython`. We send no real DNS packets through our HTTP client — these
are direct system DNS queries.

WHOIS/expiry uses RDAP (RFC 9083) via rdap.org — no extra dependency. Some
TLDs (notably .uk, some ccTLDs) don't expose expiry over public RDAP; in
that case the check returns info and moves on.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Domain ⟨apex⟩ EXPIRED ⟨value⟩ days ago | Renew the domain immediately and verify auto-renew is enabled with the registrar. |
| high | Domain ⟨apex⟩ expires in ⟨days⟩ day(s) | Renew NOW. A lapsed domain takes the site offline and risks loss-to-third-party registration. |
| medium | DNSSEC partially configured on ⟨apex⟩ — DNSKEY present but no DS at parent | Submit the DS records (KSK digest) to the registrar via the domain control panel. This typically lives under 'DNSSEC' or 'Security' in the registrar UI. |
| medium | Domain ⟨apex⟩ expires in ⟨days⟩ day(s) | Verify auto-renew with the registrar. Set a calendar reminder if unsure. |
| medium | No SPF record on ⟨apex⟩ | Publish an SPF record. Minimum for a site that doesn't send mail: v=spf1 -all Or, if mail comes from your hosting provider, the provider's published include + ~all: v=spf1 include:_spf.providerhost.com ~all |
| medium/info | SPF present on ⟨apex⟩: ⟨value⟩ | Tighten SPF to `-all` (hard fail) instead of `+all` / `?all` (no enforcement). / No action needed. |
| low/info | DMARC present on _dmarc.⟨apex⟩ | Move from p=none → p=quarantine → p=reject as your reports stabilize. / No action needed. |
| low | DNSSEC not configured on ⟨apex⟩ | Enable DNSSEC at the registrar AND at the authoritative DNS provider. Most registrars now expose a one-click toggle that coordinates DS + DNSKEY publication. |
| low | No DMARC record at _dmarc.⟨apex⟩ | — |
| low | No MTA-STS record on _mta-sts.⟨apex⟩ | Publish `v=STSv1; id=<YYYYMMDDhhmm>` TXT at _mta-sts.⟨apex⟩ and host the policy file at https://mta-sts.⟨apex⟩/.well-known/mta-sts.txt with `mode: enforce`. Start in `mode: testing` while you verify rua reports arrive cleanly. |
| info | BIMI record published on default._bimi.⟨apex⟩ | No action needed. |
| info | DKIM selector '⟨selector⟩' is published | No action needed. |
| info | DNS security check skipped (target is IP / localhost) | No action needed. |
| info | DNSSEC chain present for ⟨apex⟩ (DS + DNSKEY) | No action needed. |
| info | DNSSEC check skipped — dnspython not installed | `pip install dnspython` to enable DNSSEC + MX checks. |
| info | MTA-STS published on _mta-sts.⟨apex⟩ | Verify the policy file at https://mta-sts.⟨apex⟩/.well-known/mta-sts.txt also resolves with `mode: enforce`; the TXT record alone is the version pointer — receiving servers fetch the policy file. |
| info | No DKIM record found at the common selectors for ⟨apex⟩ | Verify DKIM via your mail provider's docs and the actual selector they publish. If the site doesn't send mail (-all SPF), DKIM isn't strictly needed. |
| info | No TLS-RPT record on _smtp._tls.⟨apex⟩ | Publish `v=TLSRPTv1; rua=mailto:tls-reports@⟨apex⟩` TXT at _smtp._tls.⟨apex⟩. |
| info | TLS-RPT published on _smtp._tls.⟨apex⟩ | No action needed. |

## Evidence the check records

- Domain ⟨apex⟩ EXPIRED ⟨value⟩ days ago: RDAP expiration: ⟨event_date⟩
- Domain ⟨apex⟩ expires in ⟨days⟩ day(s): RDAP expiration: ⟨event_date⟩
- Domain ⟨apex⟩ expires in ⟨days⟩ day(s): RDAP expiration: ⟨event_date⟩
- No MTA-STS record on _mta-sts.⟨apex⟩: Without MTA-STS, inbound mail can be downgraded to plaintext SMTP by a network attacker even if both ends support STARTTLS — there is no signal to the sender that TLS was expected.
- No TLS-RPT record on _smtp._tls.⟨apex⟩: TLS-RPT delivers daily reports about TLS handshake failures on inbound mail. Without it you can't tell whether MTA-STS is actually being honored by senders.
- DNSSEC not configured on ⟨apex⟩: No DS at the parent and no DNSKEY at the apex. The zone is not signed; recursive resolvers cannot detect cache-poisoning attacks against this domain.
- DNS security check skipped (target is IP / localhost): target host: ⟨host⟩
- No SPF record on ⟨apex⟩: No `v=spf1 ...` TXT record at the apex. Mail purporting to come from this domain can't be verified by recipient servers, making spoofing trivial.
- SPF present on ⟨apex⟩: ⟨value⟩: TXT record: ⟨spf⟩
- No DMARC record at _dmarc.⟨apex⟩: Without DMARC, SPF/DKIM failures don't actually reject spoofed mail.
- DMARC present on _dmarc.⟨apex⟩: TXT record: ⟨value⟩ ⟨note⟩
- No DKIM record found at the common selectors for ⟨apex⟩: Checked: default, selector1, google, k1. DKIM uses arbitrary selector names, so absence here isn't conclusive — your provider may use a different selector.
- MTA-STS published on _mta-sts.⟨apex⟩: TXT record: ⟨value⟩
- TLS-RPT published on _smtp._tls.⟨apex⟩: TXT record: ⟨value⟩
- BIMI record published on default._bimi.⟨apex⟩: TXT record: ⟨value⟩
- DNSSEC chain present for ⟨apex⟩ (DS + DNSKEY): Both DS (parent-side) and DNSKEY (apex-side) records resolve. Spoofing attacks against a validating resolver should fail.
- DNSSEC partially configured on ⟨apex⟩ — DNSKEY present but no DS at parent: The apex has DNSKEY records but the parent zone has no DS. Validating resolvers will treat the zone as INSECURE, defeating DNSSEC's tamper-detection.
- DKIM selector '⟨selector⟩' is published: Found DKIM at ⟨selector⟩._domainkey.⟨apex⟩
- DNSSEC check skipped — dnspython not installed: The optional `dnspython` dependency is not present.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Email authentication records (SPF / DMARC / DKIM):
dig +short TXT {host}
dig +short TXT _dmarc.{host}
dig +short TXT default._domainkey.{host}
# Or on Windows:
nslookup -type=TXT {host}
nslookup -type=TXT _dmarc.{host}
# Online grader: https://www.dmarcanalyzer.com/dmarc-record-check/?domain={host}
# Then harden in your DNS provider — set 'v=spf1 ... -all' and 'v=DMARC1; p=quarantine; rua=mailto:...'
```

## Compliance mapping

- **compliance_map / pci_dss**: 12.3
- **compliance_map / nist_800_53**: SC-20
- **compliance_map / iso_27001**: A.5.7
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-8
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.f
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 4.9
- **compliance_v2 / iso_27001_2022**: A.8.20

## References

- https://mta-sts
- https://rdap.org/domain/
- https://mxtoolbox.com/SuperTool.aspx?action=mta-sts%3a
- https://mxtoolbox.com/SuperTool.aspx?action=tls-rpt%3a
- https://dnssec-analyzer.verisignlabs.com/
- https://mxtoolbox.com/SuperTool.aspx?action=spf%3a
- https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a
- https://mxtoolbox.com/SuperTool.aspx?action=dkim%3a
- https://bimigroup.org/

## Run only this check

```
wpsecscan only dns_security https://example.com
```

`only` runs this check alone and prints its findings.
