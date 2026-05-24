# Sitemap-driven CVE pattern probe

**check_id**: `sitemap_cve_probe`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only sitemap_cve_probe
```
