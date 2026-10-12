---
id: default_creds
title: "Default credentials probe"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Authentication & session"
words: 248
---

# Default credentials probe

**check_id**: `default_creds`
**aggressive**: yes
**category**: Authentication & session
**max severity**: critical
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078.001 — Default Accounts

## What it does

Default-credentials probe — strictly capped at 10 attempts against
well-known *shipped* defaults from plugin/theme install guides.

This is NOT brute force. It tests one specific question: "did anyone leave
the install-wizard's default credentials in place?" The list never grows
beyond 10; module-load asserts that bound. Each attempt is paced 3s apart;
if the site throttles, we abort.

Opt-in via aggressive mode only.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Default credentials accepted: ⟨user⟩ / ⟨pwd⟩ | Log in as '⟨user⟩' and change the password right now. Audit the account's recent activity (Tools → Site Health, plus any audit-log plugin). Rotate ALL administrator passwords and force a session refresh (plugins like 'WP Logout Everyone' help). Consider 2FA going forward. |
| info | All ⟨attempted⟩ known default credentials were rejected | No action needed for this check. Consider an offline password audit (`hashcat -m 400 wp_users.txt rockyou.txt`). |
| info | Default-credentials probe skipped — ⟨value⟩ can ban scanner IP | Allowlist your scanner IP in the security plugin, then re-run with --ignore-lockout-risk. Or test default credentials manually via the admin login. |
| info | Default-credentials probe skipped: /wp-login.php not reachable | No action needed. |
| info | Default-creds probe aborted after ⟨attempted⟩ attempt(s) — throttling kicked in | No action needed — the throttling itself is the defense working. |

## Evidence the check records

- Default-credentials probe skipped — ⟨value⟩ can ban scanner IP: Detected: ⟨value⟩. These plugins/WAFs ban source IPs after a small number of failed login attempts. Running this check could permanently lock out your scanner machine.
- Default-credentials probe skipped: /wp-login.php not reachable: GET /wp-login.php -&gt; ⟨value⟩; this site likely uses a moved-login plugin or blocks /wp-login.php at the WAF.
- All ⟨attempted⟩ known default credentials were rejected: Tried ⟨attempted⟩ documented install-default credential pairs (admin/admin, demo/demo, etc.). None succeeded. Note this is a tiny set — passwords could still be weak in ways this check doesn't see. For a real password audit, dump wp_users and run hashcat locally.
- Default credentials accepted: ⟨user⟩ / ⟨pwd⟩: POST /wp-login.php with log=⟨user⟩ pwd=⟨pwd⟩ -&gt; HTTP ⟨status⟩ ⟨snippet⟩ This is one of the documented install-defaults — change the password immediately.
- Default-creds probe aborted after ⟨attempted⟩ attempt(s) — throttling kicked in: Attempt #⟨attempted⟩ (user=⟨user⟩) returned HTTP ⟨status⟩ with throttle markers in body. This is good for security — but it also means we can't finish the probe. If you want full coverage, whitelist your scanner IP at the WAF and re-run.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2.2
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17
- **compliance_v2 / hitrust**: 01.f
- **compliance_v2 / cmmc**: IA.L1-3.5.5
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## References

- primary: https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password

## Run only this check

```
wpsecscan only default_creds https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
