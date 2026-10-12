---
id: users
title: "User enumeration"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 171
---

# User enumeration

**check_id**: `users`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.002 — Gather Victim Identity Information: Email Addresses

## What it does

User enumeration check.

Tries four unauthenticated routes and reports each that discloses usernames
(medium): /?author=1 to 5, where a redirect to /author/&lt;slug&gt;/ reveals the
login slug; /wp-json/wp/v2/users; /wp-json/wp/v2/posts?_embed=1, which can
leak the author object even when the users endpoint is closed; and
/?rest_route=/wp/v2/users. Discovered names are stored in
ctx['shared']['users'] for downstream checks. If no route leaks, one info
finding is emitted. Fix: remove the users endpoint with the rest_endpoints
filter, redirect author archives, or use a security plugin setting.

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | REST /wp-json/wp/v2/users exposes ⟨count⟩ user(s) | Restrict the users REST endpoint. In functions.php: add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); unset($e['/wp/v2/users/(?P&lt;id&gt;[\d]+)']); return $e; }); Or use a security plugin's REST hardening rule. |
| medium | REST author leak via ?_embed exposes ⟨count⟩ user(s) | Strip embedded author data from /posts. In functions.php: add_filter('rest_prepare_post', function($r) { if (isset($r-&gt;data['_links']['author'])) unset($r-&gt;data['_links']['author']); return $r; }); Or, more aggressively, override the author embed in rest_prepare_user. |
| medium | REST users endpoint exposed via ?rest_route= query (⟨count⟩ user(s)) | Same fix as /wp-json/wp/v2/users — filter out the users endpoint via rest_endpoints. |
| medium | User enumeration via /?author=N possible (⟨count⟩ usernames disclosed) | Block author archive redirects: in functions.php, add a check that redirects /?author=N to home when not logged in. Or use a security plugin (Wordfence, iThemes Security) that has a 'disable user enumeration' setting. |
| info | No user enumeration vectors detected | No action needed. |

## Evidence the check records

- User enumeration via /?author=N possible (⟨count⟩ usernames disclosed): GET /?author=N redirects revealed: ⟨lines⟩
- No user enumeration vectors detected: Tried /?author=1..5 (no redirects), /wp-json/wp/v2/users, /?rest_route= variant.
- REST /wp-json/wp/v2/users exposes ⟨count⟩ user(s): Public REST endpoint returned: ⟨lines⟩
- REST author leak via ?_embed exposes ⟨count⟩ user(s): GET /wp-json/wp/v2/posts?_embed=1 -&gt; 200 The _embedded.author array carries author slugs even when the /wp/v2/users endpoint is locked down. WP enables _embed by default. Disclosed: ⟨lines⟩
- REST users endpoint exposed via ?rest_route= query (⟨count⟩ user(s)): /?rest_route=/wp/v2/users returned ⟨count⟩ user(s).

## Suggested fix

Block ?author= and REST user enumeration. Where to apply it: functions.php.

```php
// Block /?author=N redirects
add_action('template_redirect', function(){
    if (!empty($_GET['author']) && is_numeric($_GET['author'])) {
        wp_redirect(home_url(), 301); exit;
    }
});
// Strip users endpoint from REST
add_filter('rest_endpoints', function($endpoints){
    unset($endpoints['/wp/v2/users']);
    unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    return $endpoints;
});
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/wp-json/wp/v2/users
curl -sI https://example.com/?author=1
curl -s https://example.com/?rest_route=/wp/v2/users
```

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.18
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan only users https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
