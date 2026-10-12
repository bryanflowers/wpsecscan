---
id: upload_path_predictable
title: "Predictable upload paths"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 108
---

# Predictable upload paths

**check_id**: `upload_path_predictable`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Predictable upload-path probe.

WordPress stores uploads at /wp-content/uploads/YYYY/MM/&lt;file&gt;. If directory
listing is off but the admin uploads files with predictable names (logo.png,
admin-screenshot.png, draft.pdf), an attacker can guess and access "private"
uploads that aren't linked from any page.

Probes ~20 common admin-uploaded filenames in the current month/year folder.
GET-only, low rate.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ predictable-name file(s) reachable in /wp-content/uploads/ | (1) Rename sensitive uploads to include a hash or random suffix. (2) For truly-private files, use a plugin that serves uploads through PHP with auth (e.g. WP-Members, Restrict File Access) instead of leaving them at the public uploads URL. (3) Or add `<Files "*.pdf">Require all denied</Files>` to the uploads .htaccess and serve restricted files via a signed-URL plugin. |
| info | No predictable-name uploads found in current/previous month | No action. |

## Evidence the check records

- ⟨count⟩ predictable-name file(s) reachable in /wp-content/uploads/: Found: ⟨sample⟩ These uploads aren't linked from the public site but are reachable by guessing the filename. Admin-uploaded 'private' files (drafts, internal docs, member exports) can leak this way even when directory listing is disabled.
- No predictable-name uploads found in current/previous month: Probed ⟨value⟩ common admin-uploaded filenames in /wp-content/uploads/.

## Compliance mapping

- **compliance_map / pci_dss**: 9.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only upload_path_predictable https://example.com
```

`only` runs this check alone and prints its findings.
