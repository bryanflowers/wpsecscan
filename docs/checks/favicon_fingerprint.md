---
id: favicon_fingerprint
title: "Favicon fingerprint"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 131
---

# Favicon fingerprint

**check_id**: `favicon_fingerprint`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Favicon fingerprinting — MD5/SHA1 plus the Shodan-compatible MMH3 hash.

Hash the favicon and report it. Useful for two reasons:
  1. Threat-intel feeds (Shodan, Censys) index sites by favicon hash —
     yours being indexable means it's findable by attackers searching for
     specific stacks.
  2. Default-favicon collisions tell you the site is "stock" (no branding
     in place), which often correlates with overall security posture.

One fetch, all the hashes — both MMH3 (Shodan/Censys lookups) and MD5/SHA1
(operational fingerprint).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Favicon fingerprint (mmh3=⟨mmh3⟩, md5=⟨value⟩, ⟨count⟩ B) | Not a vulnerability by itself. If you'd rather not be indexed by favicon: serve a unique favicon per site, or 404 on /favicon.ico. If you see compromised-looking sites sharing your hash, your favicon was scraped and reused. |
| info | No /favicon.ico served (or empty) | No action needed unless you intend to serve a favicon. |

## Evidence the check records

- Favicon fingerprint (mmh3=⟨mmh3⟩, md5=⟨value⟩, ⟨count⟩ B): MMH3 (Shodan/Censys): ⟨mmh3⟩ MD5: ⟨md5⟩ SHA1: ⟨sha1⟩ Size: ⟨count⟩ bytes (base64 length: ⟨b64_len⟩ chars) Find OTHER sites with the same favicon (often: same admin, same hosting cluster, or sites compromised by the same actor): Shodan: ⟨shodan_url⟩ Censys: ⟨censys_url⟩
- No /favicon.ico served (or empty): GET /favicon.ico -&gt; ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1

## References

- https://www.shodan.io/search?query=http.favicon.hash%3A
- https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A

## Run only this check

```
wpsecscan only favicon_fingerprint https://example.com
```

`only` runs this check alone and prints its findings.
