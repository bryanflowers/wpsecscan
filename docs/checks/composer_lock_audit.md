---
id: composer_lock_audit
title: "composer.lock exposure + CVE check (#59)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 84
---

# composer.lock exposure + CVE check (#59)

**check_id**: `composer_lock_audit`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

composer.lock exposure + known-vulnerable-version detection.

Round-64 #59 — many WP devs run `composer install` at the docroot,
which leaks composer.lock + composer.json. The file is read-only but
discloses every PHP-dependency version, making vuln-mapping trivial for
an attacker. We probe a handful of likely paths and, if exposed, parse
the lock for a small curated list of high-impact known-vulnerable
versions.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Known-vulnerable dependency: ⟨pkg_name⟩ ⟨pkg_ver⟩ | Run: composer update ⟨pkg_name⟩ -- pin to &gt; ⟨max_vuln⟩ |
| medium/low | composer dependency file exposed at ⟨path⟩ | Block public access to composer.lock / composer.json: Apache: &lt;Files ~ "composer\.(json\|lock)$"&gt; Require all denied &lt;/Files&gt; Nginx: location ~* /composer\.(json\|lock)$ { deny all; } Then audit the listed dependencies for known CVEs (composer audit). |

## Evidence the check records

- composer dependency file exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes)
- Known-vulnerable dependency: ⟨pkg_name⟩ ⟨pkg_ver⟩: composer.lock declares ⟨pkg_name⟩ @ ⟨pkg_ver⟩ CVE: ⟨ref⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.2
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only composer_lock_audit https://example.com
```

`only` runs this check alone and prints its findings.
