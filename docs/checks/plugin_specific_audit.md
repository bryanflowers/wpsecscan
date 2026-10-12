---
id: plugin_specific_audit
title: "ACF/MS/agent/child/WP-CLI audit (#11-15)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 168
---

# ACF/MS/agent/child/WP-CLI audit (#11-15)

**check_id**: `plugin_specific_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#10-15 — Plugin-specific deep audits in one module.

#10 Gravity Forms file-upload MIME-confusion probe (aggressive)
#11 ACF Pro license JWT leak scan
#12 Multisite tenant-isolation probe
#13 ManageWP / MainWP / iThemes Sync agent detection
#14 Child-theme override fingerprint
#15 WP-CLI exposure (`/wp-cli.phar`, command-passthrough hacks)

## Request footprint

The module contains 4 request call(s) to the target (GET x2, HEAD x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | ACF Pro license JWT leaked in front-end HTML | Rotate the ACF Pro license at https://www.advancedcustomfields.com/my-account/. Audit the plugin/theme that's calling wp_localize_script() with the license value — never expose it on the public side. |
| critical | WP-CLI artifact accessible: ⟨p⟩ | Delete ⟨p⟩. wp-cli should NEVER live in the web root. Install via `composer global require wp-cli/wp-cli` instead, and keep it outside the doc root. |
| medium | Multisite REST: users from ⟨count⟩ blogs returned in one call | Filter REST users by current blog OR require admin. The `pre_get_users` filter can scope `blog_id = get_current_blog_id()`. |
| low | Remote-management agent detected: ⟨label⟩ | Confirm the agent is intentional. If you're not using ⟨label⟩, deactivate + delete the plugin (attack surface — these tools have had RCEs historically). |
| info | Child theme detected: ⟨value⟩ | Audit the child theme's `functions.php` for security hardening that might be overriding parent-theme defaults (e.g., removing nonce checks, or echoing user input without escape). |
| info | Gravity Forms upload-bypass probe — manual follow-up | Set GF's file-type allow-list explicitly (no `*` wildcards). Add `disable_php_execution` in the upload directory's nginx config. |
| info | Plugin-specific deep audit — clean | No action. |

## Evidence the check records

- Gravity Forms upload-bypass probe — manual follow-up: Automated GF upload-bypass requires a CSRF-fresh form session + valid nonce. Use Burp Suite's `Intruder` against the form's `upload_file_X` field.
- ACF Pro license JWT leaked in front-end HTML: Matched pattern: ⟨value⟩...⟨value⟩
- Remote-management agent detected: ⟨label⟩: ⟨path⟩ responds 200 OK.
- Child theme detected: ⟨value⟩: Multiple theme directories serve assets — likely a parent + child setup.
- Plugin-specific deep audit — clean: No ACF/MS/agent/child/WP-CLI red flags.
- WP-CLI artifact accessible: ⟨p⟩: ⟨p⟩ returned 200. wp-cli.phar in the web root is a full RCE waiting to happen if PHP exec is on.
- Multisite REST: users from ⟨count⟩ blogs returned in one call: GET /wp-json/wp/v2/users returned users with blog_ids ⟨value⟩ — cross-tenant info leak.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## References

- https://www.advancedcustomfields.com/my-account/

## Run only this check

```
wpsecscan only plugin_specific_audit https://example.com
```

`only` runs this check alone and prints its findings.
