---
id: dns_deep
title: "DNS deep — DNSSEC/CAA/TXT-secret/DoH/PTR/wildcard (#32-39)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 180
---

# DNS deep — DNSSEC/CAA/TXT-secret/DoH/PTR/wildcard (#32-39)

**check_id**: `dns_deep`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: critical
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

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Secret pattern in TXT records on ⟨apex⟩ | ROTATE these credentials IMMEDIATELY (they're public). Replace the TXT verification with a fresh token that you delete after the verifying party confirms. |
| medium | Wildcard DNS record active on *.⟨apex⟩ | Wildcard A/CNAME records make subdomain enumeration noisy and increase phishing risk (attackers register `paypal-update.victim.com` and it just works). Replace with explicit records or a 404 server-block. |
| low | No CAA record on ⟨apex⟩ | Publish CAA to restrict which CAs may issue certs for the domain. Example: ⟨apex⟩. CAA 0 issue "letsencrypt.org" ⟨apex⟩. CAA 0 issuewild ";" (disallow wildcards) |
| low | No DNSSEC (DNSKEY) for ⟨apex⟩ | Enable DNSSEC at your registrar + DNS host. Mitigates cache-poisoning + improves MTA-STS / DANE assurance. Most providers (Cloudflare, Route 53, Bunny) are one-click. |
| info | DNS-deep audit — all checks clean | No action. |
| info | DNS-deep skipped (IP/localhost) | No action. |
| info | DNSSEC active on ⟨apex⟩ | No action. |
| info | HTTPS SVCB record published for ⟨apex⟩ | No action — clients can discover HTTP/3 + DoH endpoints via this record. |
| info | In-bailiwick NS records found for ⟨apex⟩ | No action — glue records are correctly published. |
| info | PTR for ⟨apex⟩ does not match | Reverse-DNS mismatch is normal for shared hosting / CDNs. For dedicated mail-sending IPs, the PTR should match the HELO/EHLO hostname. |
| info | Recursive resolver: ⟨resolver⟩ | Informational — confirms which resolver the scanner host uses. |

## Evidence the check records

- DNS-deep skipped (IP/localhost): host=⟨host⟩
- No DNSSEC (DNSKEY) for ⟨apex⟩: No DNSKEY records returned.
- DNSSEC active on ⟨apex⟩: DNSKEY present.
- No CAA record on ⟨apex⟩: No `CAA 0 issue ...` records.
- HTTPS SVCB record published for ⟨apex⟩: ⟨value⟩
- Recursive resolver: ⟨resolver⟩: Detected via well-known resolver-fingerprint queries.
- Wildcard DNS record active on *.⟨apex⟩: ⟨rand⟩.⟨apex⟩ resolves to ⟨wild_ip⟩
- PTR for ⟨apex⟩ does not match: ⟨apex⟩ -&gt; ⟨apex_ip⟩ -&gt; ⟨rev⟩

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
wpsecscan only dns_deep https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
