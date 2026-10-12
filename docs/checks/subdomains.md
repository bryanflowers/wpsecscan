---
id: subdomains
title: "Subdomain discovery"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 131
---

# Subdomain discovery

**check_id**: `subdomains`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — Gather Victim Network: IP Addresses

## What it does

Subdomain discovery via certificate transparency (crt.sh).

For each discovered subdomain, do a quick DNS resolve + HTTP probe to flag:
  - Subdomains pointing to dangling CDN providers (takeover candidates)
  - Subdomains exposing dev/staging/admin panels

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | COOKIE-TOSSING CHAIN: takeover-able subdomain + apex-scoped cookies | 1. Fix the takeover candidate FIRST (reclaim the SaaS resource or delete the DNS record). 2. Restrict the main site's session cookies to the HOST scope only (omit the Domain= attribute, or set it to the exact apex without leading dot). |
| critical | ⟨count⟩ CONFIRMED subdomain takeover candidate(s) | These subdomains have DNS records pointing to a CDN/SaaS provider that returns an 'unclaimed/missing' page — meaning anyone can register the resource on that provider and serve content from YOUR subdomain. Either: 1. Reclaim the resource on the SaaS provider (recreate the GitHub Pages repo, the Heroku app, the S3 bucket, etc.) — see the per-vendor registrar URLs in the evidence above. 2. Remove the dangling DNS record (CNAME / A) immediately. Real-world impact: cookie hijacking (subdomain cookies leak), phishing under your brand, malware distribution from your domain, email DMARC bypass. |
| low | ⟨count⟩ subdomain(s) with sensitive labels | Audit each — staging/dev/admin panels should be behind a VPN or IP allow-list, not publicly indexable. Certificate transparency makes them effectively public. |
| info | No subdomains found via certificate transparency for ⟨apex⟩ | No action needed. |
| info | Subdomain discovery skipped (target is an IP or localhost) | No action needed. |
| info | ⟨count⟩ subdomain(s) discovered via crt.sh for ⟨apex⟩ | No action needed unless you didn't intend these subdomains to be public. |

## Evidence the check records

- ⟨count⟩ subdomain(s) discovered via crt.sh for ⟨apex⟩: First 10: ⟨value⟩
- Subdomain discovery skipped (target is an IP or localhost): target host: ⟨host⟩
- No subdomains found via certificate transparency for ⟨apex⟩: crt.sh returned no records (or the query failed).
- COOKIE-TOSSING CHAIN: takeover-able subdomain + apex-scoped cookies: Takeover candidates: ⟨value⟩ Main site sets cookies on `.⟨apex⟩` (apex scope). An attacker who claims the dangling SaaS resource can set cookies on `.{apex}` from that subdomain. The victim's browser will then SEND that attacker-controlled cookie to the MAIN site on the next visit — session-fixation / session-hijack.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s 'https://crt.sh/?q=%25.{host}&output=json' | jq -r '.[].name_value' | sort -u
# Manual takeover check for a suspect subdomain:
host <subdomain>
curl -sI https://<subdomain>/
```

## Compliance mapping

- **compliance_map / pci_dss**: 11.3.1
- **compliance_map / nist_800_53**: CA-8
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-04
- **compliance_v2 / cis_v8**: 1.1
- **compliance_v2 / iso_27001_2022**: A.5.9

## References

- primary: https://github.com/EdOverflow/can-i-take-over-xyz
- deep dive: https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover
- https://pages.github.com/
- https://dashboard.heroku.com/new-app
- https://portal.azure.com/
- https://s3.console.aws.amazon.com/
- https://readme.io/
- https://www.zendesk.com/register/
- https://manage.fastly.com/
- https://app.netlify.com/
- https://ghost.org/
- https://app.intercom.com/
- https://www.strikingly.com/s/sign_up
- https://www.tumblr.com/register
- https://www.uservoice.com/sign-up/
- https://my.wpengine.com/
- https://www.shopify.com/
- https://www.squarespace.com/
- https://manage.statuspage.io/
- https://www.teamwork.com/sign-up
- https://app.unbounce.com/
- https://app.wishpond.com/
- https://my.kinsta.com/
- https://www.agilecrm.com/
- https://dashboard.smartling.com/
- https://www.animaapp.com/
- https://www.wishpond.com/404?campaign=true
- https://crt.sh/?q=%25

## Run only this check

```
wpsecscan only subdomains https://example.com
```

`only` runs this check alone and prints its findings.
