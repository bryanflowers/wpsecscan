---
id: ajax_surface
title: "admin-ajax action surface"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "Discovery & enumeration"
words: 222
---

# admin-ajax action surface

**check_id**: `ajax_surface`
**aggressive**: yes
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WordPress AJAX action surface audit.

`admin-ajax.php?action=<name>` is one of the most common WP vulnerability
vectors — plugins register handlers via `add_action('wp_ajax_nopriv_<name>',...)`
and many forget to check capabilities or nonces.

This check:
  1. Confirms /wp-admin/admin-ajax.php is reachable.
  2. Discovers action names by regex-scanning HTML/JS of a few pages.
  3. Probes each action without a nonce and looks for non-trivial responses
     (length > 1 and != "0", != "-1") that suggest the handler ran.

Hard caps for safety:
  - At most 25 actions probed per scan
  - 0.5s pacing between probes
  - GET-only (we don't try POST actions to avoid mutation side-effects)

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | AJAX action '⟨action⟩' responded to nonce-less request | Audit the plugin that registers the '⟨action⟩' action. Grep your wp-content/plugins for `wp_ajax_nopriv_⟨action⟩`. Most should call `check_ajax_referer()` + `current_user_can()` before returning anything sensitive. |
| info | AJAX surface: ⟨count⟩ action(s) discovered, ⟨count⟩ probed (cap ⟨MAX_ACTIONS⟩) | No action needed for the enumeration itself — see follow-up findings for any handlers that responded. |
| info | No AJAX action names discovered in front-end source | No action needed. |
| info | admin-ajax.php not reachable — AJAX surface check skipped | No action needed (admin-ajax may be blocked at the edge — that's good). |

## Evidence the check records

- AJAX surface: ⟨count⟩ action(s) discovered, ⟨count⟩ probed (cap ⟨MAX_ACTIONS⟩): Actions discovered in source: ⟨value⟩ Probed actions (capped at ⟨MAX_ACTIONS⟩): ⟨value⟩
- admin-ajax.php not reachable — AJAX surface check skipped: No response from /wp-admin/admin-ajax.php.
- No AJAX action names discovered in front-end source: Scanned ⟨count⟩ pages with three action= patterns; found nothing usable. (Either the site uses few AJAX handlers, or the handlers are bundled in obfuscated JS.)
- AJAX action '⟨action⟩' responded to nonce-less request: GET /wp-admin/admin-ajax.php?action=⟨action⟩ -&gt; HTTP ⟨status⟩, ⟨body_len⟩ bytes body preview: ⟨preview⟩ WP's `wp_ajax_nopriv_<action>` handlers are intentionally public, but ANY data they return for an anonymous caller is worth auditing. If the response looks like real data (not just status: 0/-1), the handler may be missing auth/capability checks.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s 'https://example.com/wp-admin/admin-ajax.php?action=<discovered-action>'
# Audit which nopriv handlers your plugins register:
grep -rE "wp_ajax_nopriv_" wp-content/plugins/ | head -50
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only ajax_surface https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
