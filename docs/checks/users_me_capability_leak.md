---
id: users_me_capability_leak
title: "REST /users/me unauthenticated capabilities"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 135
---

# REST /users/me unauthenticated capabilities

**check_id**: `users_me_capability_leak`
**aggressive**: no
**category**: Authentication & session
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

`/wp-json/wp/v2/users/me` unauthenticated capability leak.

An unauthenticated GET to /wp-json/wp/v2/users/me should return 401. If
it returns 200 with a `capabilities` map, the site has lost track of
authentication and is leaking the capability list (administrator,
editor, contributor, etc.) of whoever's WP-related cookies happen to be
on the connection. This is distinct from the author-slug leak the
`users` check probes for — it's a structural auth bypass.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high | REST /wp-json/wp/v2/users/me returns capabilities unauthenticated (role: ⟨value⟩) | Verify which plugin or theme exposed /users/me without auth. Standard WordPress requires `edit_users` capability for this route — if it's returning 200 anonymously, something has hooked `rest_endpoints` or registered a public override. Audit any custom `register_rest_route` calls in your active plugins. |
| info | /wp-json/wp/v2/users/me returns ⟨value⟩ unauthenticated (good) | No action — REST is correctly requiring authentication for /users/me. |

## Evidence the check records

- /wp-json/wp/v2/users/me returns ⟨value⟩ unauthenticated (good): Anonymous request → HTTP ⟨value⟩.
- REST /wp-json/wp/v2/users/me returns capabilities unauthenticated (role: ⟨value⟩): Anonymous GET /wp-json/wp/v2/users/me → HTTP 200 User: ⟨name⟩ Roles: ⟨role⟩ Capabilities present: ⟨count⟩ entries This indicates the REST API has lost track of authentication state, or a plugin has overridden the route to bypass `current_user_can()`. An attacker now knows which actions an unauthenticated client can perform before even attempting privilege escalation.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only users_me_capability_leak https://example.com
```

`only` runs this check alone and prints its findings.
