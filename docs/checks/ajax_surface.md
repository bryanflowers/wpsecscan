# admin-ajax action surface

**check_id**: `ajax_surface`
**aggressive**: yes
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only ajax_surface
```
