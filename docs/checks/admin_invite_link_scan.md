---
id: admin_invite_link_scan
title: "Discord/Slack/Telegram invite leak (A33)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Other"
words: 76
---

# Discord/Slack/Telegram invite leak (A33)

**check_id**: `admin_invite_link_scan`
**aggressive**: no
**category**: Other
**max severity**: low
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1071.001 — Web Protocols
**CWE**: CWE-829
**D3FEND**: D3-NTA

## What it does

A33 (v2.6.0) — Discord / Slack invite leak.

Compromised WP installs sometimes have a Slack/Discord/Telegram invite
embedded in an admin notice or sticky post — a back-channel the
attacker uses to push commands to an automated agent (or to recruit
the operator's customers into a phishing community).

Passive: scan the homepage + sitemap-listed posts (limited to first
20) for known invite URL patterns.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | ⟨count⟩ chat-invite link(s) embedded in public pages | 1. Confirm each link is intentional (community page, support). 2. If unexpected: TREAT AS COMPROMISE. Chat invites embedded without operator knowledge are a backdoor / phishing channel. 3. Search wp_options, wp_posts, and wp_postmeta for the invite URLs; the entry point is whichever table contains them. |

## Evidence the check records

- ⟨count⟩ chat-invite link(s) embedded in public pages: Invite links found: ⟨value⟩ ...

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.5.7

## Run only this check

```
wpsecscan only admin_invite_link_scan https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
