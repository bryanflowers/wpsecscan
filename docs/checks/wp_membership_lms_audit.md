---
id: wp_membership_lms_audit
title: "Membership + LMS plugin audit (#4-5)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 117
---

# Membership + LMS plugin audit (#4-5)

**check_id**: `wp_membership_lms_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-285
**D3FEND**: D3-RAC

## What it does

Round-59 #4-5 — Membership + LMS plugin audit.

#4 Membership: MemberPress, Paid Memberships Pro, Restrict Content Pro.
   Payment + access-control glue — historically the source of capability
   bypass and price-tampering CVEs.
#5 LMS: LearnDash, LifterLMS, TutorLMS, Sensei. Quiz-bypass, completion
   spoofing, certificate-IDOR are the big themes.

Each plugin's REST endpoints + protected-content paths are probed for
unauthenticated readability — the most common bug class.

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨name⟩ REST endpoint readable unauthenticated | Lock `⟨rest_path⟩` to authenticated callers via `permission_callback`. ⟨name⟩ ships defaults that are sometimes too permissive. |
| medium | ⟨name⟩ REST endpoint readable unauthenticated | Add `permission_callback` requiring at least `read` capability on `⟨rest_path⟩`. |
| info | LMS plugin: ⟨name⟩ ⟨value⟩ detected | LMS plugins commonly suffer quiz-bypass and certificate-IDOR. Audit nonce + per-user ownership checks. |
| info | Membership plugin: ⟨name⟩ ⟨value⟩ detected | Membership plugins gate paid content. Audit `permission_callback` on REST + AJAX. |
| info | Membership/LMS audit — no plugins detected | No action. |

## Evidence the check records

- Membership plugin: ⟨name⟩ ⟨value⟩ detected: ⟨plugin_path⟩ reachable.
- LMS plugin: ⟨name⟩ ⟨value⟩ detected: ⟨plugin_path⟩ reachable.
- Membership/LMS audit — no plugins detected: Probed 3 membership + 4 LMS plugins.
- ⟨name⟩ REST endpoint readable unauthenticated: GET ⟨rest_path⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes).
- ⟨name⟩ REST endpoint readable unauthenticated: GET ⟨rest_path⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes).

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only wp_membership_lms_audit https://example.com
```

`only` runs this check alone and prints its findings.
