---
id: sitemap_cve_probe
title: "Sitemap-driven CVE pattern probe"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 139
---

# Sitemap-driven CVE pattern probe

**check_id**: `sitemap_cve_probe`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: medium
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Sitemap-driven CVE probe.

Pulls `/sitemap.xml` and `/wp-sitemap.xml`, extracts every URL, then probes
each URL against a small catalog of known-vulnerable WP URL patterns:
  - `?elementor-action=...` — Essential Addons / Elementor unauth-vuln
  - `?wc-ajax=...` — WooCommerce AJAX surface
  - `?action=astoundify_...` — Astoundify framework
  - `?post_type=shop_order` admin actions (auth required)
  - `?id=N&controller=...` legacy plugin routers

Surfaces URLs that match one of these patterns AND respond differently than
their bare equivalent (status delta, body delta).

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Sitemap URL responds to vuln pattern: ⟨url⟩?⟨param⟩=... | Investigate the plugin owning this URL. The fact that adding the parameter changes the response means there's a code path that consumes the parameter — verify it's sanitised. Cross-reference the plugin slug with Wordfence/Patchstack CVE DBs. |
| info | No sitemap found — sitemap-driven CVE probe skipped | No action. |
| info | Sitemap(s) ⟨value⟩ are empty | No action. |
| info | Sitemap-driven CVE probe clean (⟨count⟩ URLs tested) | No action. |

## Evidence the check records

- No sitemap found — sitemap-driven CVE probe skipped: Tried: ⟨value⟩
- Sitemap(s) ⟨value⟩ are empty: The sitemap responded with 200 but contained no &lt;loc&gt; elements.
- Sitemap-driven CVE probe clean (⟨count⟩ URLs tested): Probed ⟨count⟩ sitemap URLs against ⟨count⟩ known vuln-pattern params; no delta responses.
- Sitemap URL responds to vuln pattern: ⟨url⟩?⟨param⟩=...: GET ⟨url⟩?⟨param⟩=&lt;test&gt; -&gt; HTTP ⟨status⟩ with content delta vs baseline Suspect vector: ⟨label⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only sitemap_cve_probe https://example.com
```

`only` runs this check alone and prints its findings.
