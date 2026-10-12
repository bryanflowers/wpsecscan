---
id: core_version
title: "WordPress core version"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 175
---

# WordPress core version

**check_id**: `core_version`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Gather Victim Host Information: Software

## What it does

WordPress core version detection.

Looks for the core version in the &lt;meta name="generator"&gt; tag on /, then in
the /feed/ &lt;generator&gt; element, and always requests /readme.html, which is
reported (medium) when it is public and shows a version. The result is stored
in ctx['shared']['wp_version'] for other checks. It then asks
api.wordpress.org for the latest release, a request that leaves the target:
older than latest is high, current is info, and an unreachable API leaves a
medium disclosure finding. No version found yields one info finding. Fix:
update core, delete readme.html and remove the wp_generator action.

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WordPress core is outdated: ⟨version⟩ (latest: ⟨latest⟩) | Update WordPress core to ⟨latest⟩ via Dashboard → Updates. Test in staging if you run heavy plugins. |
| medium | WordPress version ⟨version⟩ disclosed | Suppress version disclosure: remove the generator meta with `remove_action('wp_head','wp_generator')` and consider deleting /readme.html. |
| medium | readme.html is publicly accessible | Delete /readme.html or block it with a server-level deny rule. It serves no purpose in production and broadcasts your WP version. |
| info | WordPress core is up to date (⟨version⟩) | No action needed. |
| info | WordPress core version not disclosed via common channels | No action needed. Continue suppressing WP version disclosure. |

## Evidence the check records

- WordPress core version not disclosed via common channels: No &lt;meta generator&gt;, /readme.html, or /feed/ version leak detected.
- WordPress version ⟨version⟩ disclosed: Source: ⟨source⟩. Could not reach api.wordpress.org to compare.
- readme.html is publicly accessible: GET /readme.html → 200, leaks WordPress version ⟨value⟩
- WordPress core is outdated: ⟨version⟩ (latest: ⟨latest⟩): Detected version ⟨version⟩ via ⟨source⟩; latest stable is ⟨latest⟩.
- WordPress core is up to date (⟨version⟩): Detected ⟨version⟩ via ⟨source⟩; latest is ⟨latest⟩.

## Suggested fix

Suppress WordPress version disclosure. Where to apply it: functions.php (active theme).

```php
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');
add_filter('style_loader_src', function($src){ return remove_query_arg('ver', $src); }, 9999);
add_filter('script_loader_src', function($src){ return remove_query_arg('ver', $src); }, 9999);
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/ | grep -i 'meta name=.generator'
curl -s https://example.com/feed/ | grep -i 'generator'
curl -sI https://example.com/readme.html
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## References

- https://api.wordpress.org/core/version-check/1.7/

## Run only this check

```
wpsecscan only core_version https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
