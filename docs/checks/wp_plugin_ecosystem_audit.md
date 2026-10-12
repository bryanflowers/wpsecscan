---
id: wp_plugin_ecosystem_audit
title: "Search/SEO/Backup/SMTP/Cache/CDN/Sec/Chat plugin audit (#7,#9-15)"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 153
---

# Search/SEO/Backup/SMTP/Cache/CDN/Sec/Chat plugin audit (#7,#9-15)

**check_id**: `wp_plugin_ecosystem_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Round-59 #7, #9-15 — Plugin-ecosystem audit (search, SEO, backup, SMTP,
caching, CDN plugin, security plugin, live-chat).

Each plugin family has a canonical "leaked config/credential" path. We
fingerprint then probe that one path. False-positive rate is low —
backup-plugin SQL dumps and SMTP API keys in cleartext are the actual
worst-case secrets-in-the-web-root pattern.

#7  Search:   Relevanssi, SearchWP, Ajax Search Pro
#9  SEO:      Yoast, RankMath, AIOSEO, SEOPress — sitemap config dumps
#10 Backup:   UpdraftPlus, BackWPup, WPVivid, Duplicator — SQL/dump exposure
#11 SMTP:     WP Mail SMTP, Post SMTP, Easy WP SMTP — API key leak
#12 Caching:  W3 Total Cache, WP Super Cache, WP Rocket, Cache Enabler
#13 CDN:      CDN Enabler, Photon, Smush CDN
#14 Security: Wordfence, Sucuri, iThemes Security, AIOWPS — log paths
#15 Chat:     Tawk, LiveChat, Crisp, Tidio, Drift

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low, info) | ⟨name⟩: ⟨message⟩ | Add an empty index.html in `⟨probe_path⟩` and disable directory listing in nginx/.htaccess. Move ⟨name⟩'s data outside the web root if possible. |
| info | Plugin-ecosystem audit — none of the tracked plugins detected | No action. |
| info | ⟨label⟩ detected: ⟨count⟩ | Each ⟨value⟩ adds attack surface. Keep on the latest minor and audit its REST/AJAX surface. |

## Evidence the check records

- Plugin-ecosystem audit — none of the tracked plugins detected: Probed ⟨count⟩ plugins across 8 ecosystems.
- ⟨name⟩: ⟨message⟩: GET ⟨probe_path⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes).

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.8
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: CM-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only wp_plugin_ecosystem_audit https://example.com
```

`only` runs this check alone and prints its findings.
