# CDN edge audit — Workers/CF/Fastly/Bunny/KeyCDN (#52-57)

**check_id**: `cdn_edge_audit`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-444
**D3FEND**: D3-NTA

## What it does

Round-59 #52-57 — CDN / edge audit.

#52 Cloudflare Workers route exposure — does the apex have a Worker
   handling /api/* or /admin/* without auth?
#53 CloudFront signed-URL bypass — strip Signature= and Policy=, does
   the resource still serve?
#54 Bunny / KeyCDN config probes — Origin-Shield header presence
#55 Edge cache TTL audit — Cache-Control + Cloudflare cf-cache-status
#56 Origin-pull header injection — does the origin honour X-Original-Host
   from edge?
#57 CDN purge-API auth — is the CDN admin/purge URL reachable from the
   public network? (For each provider, the URL pattern differs.)

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.f
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only cdn_edge_audit
```
