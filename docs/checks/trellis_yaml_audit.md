---
id: trellis_yaml_audit
title: "Roots Trellis YAML exposure (N137)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 80
---

# Roots Trellis YAML exposure (N137)

**check_id**: `trellis_yaml_audit`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-538
**D3FEND**: D3-CRO

## What it does

N137 (v2.7.0) — Roots Trellis YAML anti-pattern audit.

When the existing host_platform_detect check fingerprints a Bedrock or
Roots stack, this companion probes for Trellis-specific config
exposure: group_vars/ + ansible.cfg are sometimes deployed to the
web root in mis-configured installs, leaking SSH usernames, vault
passwords, and host inventories.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Trellis / Ansible config web-reachable: ⟨path⟩ | 1. IMMEDIATE: block /group_vars/, /ansible.cfg, /site.yml at the WAF. 2. Move the Trellis tree OUT of the web root — Trellis expects to live at /srv/www/&lt;site&gt;/current/web/ with the YAML files above that path. 3. Rotate any vault-stored secret that was reachable. |

## Evidence the check records

- Trellis / Ansible config web-reachable: ⟨path⟩: GET ⟨path⟩ → HTTP 200, YAML-shaped body. Excerpt: ⟨value⟩ Trellis config typically contains SSH usernames, hostnames, and vault-encrypted secrets. Anyone on the internet can read it.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only trellis_yaml_audit https://example.com
```

`only` runs this check alone and prints its findings.
