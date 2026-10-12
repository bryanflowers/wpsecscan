---
id: wp_engine_misconfig
title: "WP Engine private-path leaks"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 130
---

# WP Engine private-path leaks

**check_id**: `wp_engine_misconfig`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WP Engine-specific misconfiguration probes.

WP Engine (the host) blocks dozens of common paths via their `wpe_common_blocked_paths`
rule — but their own private paths (/wpe_common.php, /_wpeprivate/, /wp-config.txt) are
occasionally reachable on misconfigured sites.

Only runs against sites that fingerprint as WP Engine (X-Powered-By: WP Engine
or Server: nginx-wpengine).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium | WP Engine private path reachable: ⟨p⟩ (HTTP ⟨code⟩) | If the site is still on WP Engine: open a support ticket — their CDN rule isn't filtering this path. If the site has migrated, remove the WP Engine mu-plugins from /wp-content/mu-plugins/ and rebuild caches. |
| info | Host is not WP Engine — WP Engine-specific probes skipped | No action. |
| info | WP Engine host detected, no private-path leaks | No action. |

## Evidence the check records

- Host is not WP Engine — WP Engine-specific probes skipped: No WP Engine fingerprint in server headers or homepage HTML.
- WP Engine host detected, no private-path leaks: Probed ⟨count⟩ WP Engine private paths; all returned 404.
- WP Engine private path reachable: ⟨p⟩ (HTTP ⟨code⟩): GET ⟨p⟩ -&gt; ⟨code⟩. WP Engine's `wpe_common_blocked_paths` should return 404 for this. A reachable response suggests a rule misconfiguration or the site has been moved off WP Engine without fully migrating away from their private code.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only wp_engine_misconfig https://example.com
```

`only` runs this check alone and prints its findings.
