---
id: hostname_collision
title: "Apex vs www hostname collision"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 191
---

# Apex vs www hostname collision

**check_id**: `hostname_collision`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1583.001 — Acquire Infrastructure: Domains
**CWE**: CWE-346
**D3FEND**: D3-DNSTI

## What it does

H8 Hostname collision detector.

If `www.target.com` and `target.com` resolve to different servers — or
serve different sites — that's almost always a config mistake. Worse: an
attacker who claims the apex (or vice-versa) can serve content under YOUR
brand. Also catches cases where `target.com` is parked while `www.` is the
real site (or vice-versa).

Compares the homepages of `apex` vs `www.apex`:
  - Same fingerprint (favicon hash, title, body length) → fine
  - Different status codes (one 200, other 404/30x to a parking page) → flagged
  - Different content → flagged as potential subdomain takeover

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Hostname collision: ⟨apex_host⟩ and ⟨www_host⟩ serve different content | Pick a canonical hostname (usually with `www.`), and 301-redirect the other to it via the web server config. Nginx example: server { server_name apex.com; return 301 https://www.apex.com$request_uri; } |
| info | Hostname collision check clean (⟨apex_host⟩ and ⟨www_host⟩ serve the same site) | No action. |
| info | Hostname collision — one variant unreachable (⟨apex_host⟩ or ⟨www_host⟩) | Ensure both apex and www point at the same site (CNAME or A record). |

## Evidence the check records

- Hostname collision: ⟨apex_host⟩ and ⟨www_host⟩ serve different content: ⟨apex_url⟩ -&gt; HTTP ⟨apex_status⟩ (⟨apex_len⟩ bytes) ⟨www_url⟩ -&gt; HTTP ⟨www_status⟩ (⟨www_len⟩ bytes) This is usually a config mistake: one hostname is the real site, the other is parked or uncontrolled. If an attacker can claim the unused variant (e.g. via subdomain takeover), they can serve content under your domain.
- Hostname collision — one variant unreachable (⟨apex_host⟩ or ⟨www_host⟩): apex reachable: ⟨value⟩; www reachable: ⟨value⟩
- Hostname collision check clean (⟨apex_host⟩ and ⟨www_host⟩ serve the same site): Both returned HTTP ⟨apex_status⟩ with bodies of ⟨apex_len⟩ / ⟨www_len⟩ bytes.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## References

- https://www.apex.com$request_uri

## Run only this check

```
wpsecscan only hostname_collision https://example.com
```

`only` runs this check alone and prints its findings.
