---
id: cdn_edge_audit
title: "CDN edge audit — Workers/CF/Fastly/Bunny/KeyCDN (#52-57)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 196
---

# CDN edge audit — Workers/CF/Fastly/Bunny/KeyCDN (#52-57)

**check_id**: `cdn_edge_audit`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
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

## Request footprint

The module contains 5 request call(s) to the target (GET x5). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Origin reflects X-Forwarded-Host into HTML | In nginx, never use `$http_x_forwarded_host` unless you've allow-listed trusted upstreams. Pin `Host` from a constant on the CDN. |
| medium/info | CDN purge endpoint reachable: ⟨path⟩ -&gt; ⟨value⟩ | If 200 from anon, this is critical. Lock the purge URL to the CDN provider's IPs or require an API key in the request. |
| low | Edge cache effectively disabled (Cache-Control: max-age=0) | If using a CDN, set `Cache-Control: public, max-age=300, s-maxage=86400` for HTML; long max-age for static. Otherwise edge is just a TLS terminator. |
| low | Possible Cloudflare Worker route: ⟨path⟩ | Audit the Worker source. Common bug: no auth on `/api/admin/*` because the Worker assumes Cloudflare Access is in front. |
| info | Bunny/KeyCDN detected without Origin-Shield | Enable Origin Shield in the dashboard to reduce origin load + bandwidth cost. Not a security issue but cost-affecting. |
| info | CDN(s) detected: ⟨value⟩ | No action. |
| info | CDN-edge audit — clean (no CDN detected or no issues) | No action. |
| info | CDN-edge skipped (no home) | No action. |
| info | CloudFront: signed-URL params accepted on public path | If you intend `/` to be public, ignore this. If `/private/*` should be signed-only, configure the distribution's `Trusted Signers` and verify 401/403 is returned without a valid Signature. |
| info | Cloudflare cache status: ⟨cf_cache⟩ | If this is unintentional, check page rules / cache levels in the Cloudflare dashboard. |

## Evidence the check records

- Edge cache effectively disabled (Cache-Control: max-age=0): Cache-Control: ⟨cc⟩
- Cloudflare cache status: ⟨cf_cache⟩: cf-cache-status: ⟨cf_cache⟩
- CloudFront: signed-URL params accepted on public path: GET /?Signature=foo... -&gt; 200. Origin ignored bogus signature, which is normal IF the cache behaviour isn't restricted to signed URLs.
- Bunny/KeyCDN detected without Origin-Shield: No `origin-shield` header.
- Origin reflects X-Forwarded-Host into HTML: X-Forwarded-Host: attacker.example reflected in response body. Combined with cache poisoning, attackers can rewrite resources to load from their domain.
- CDN purge endpoint reachable: ⟨path⟩ -&gt; ⟨value⟩: GET ⟨path⟩ -&gt; ⟨value⟩
- Possible Cloudflare Worker route: ⟨path⟩: GET ⟨path⟩ -&gt; 200 (len=⟨count⟩). Headers suggest Worker.

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
wpsecscan only cdn_edge_audit https://example.com
```

`only` runs this check alone and prints its findings.
