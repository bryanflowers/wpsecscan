---
id: login_throttle_deep
title: "Deep throttle mapping (opt-in, 20 min)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 269
---

# Deep throttle mapping (opt-in, 20 min)

**check_id**: `login_throttle_deep`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.003 — Brute Force: Password Spraying

## What it does

Deep login-throttle mapper.

Sends N deliberately-wrong logins for a single synthetic non-existent user
(one attempt every `pacing` seconds — default 10, range 5-60). Records when
the response shape changes —
status code goes 4xx/5xx, body length jumps, captcha markers appear — and
reports the threshold ("locks out at attempt 14, ~3 min in") or confirms no
threshold up to the cap.

NOT brute force. The username is synthetic (random nonce, cannot exist),
the password is a fixed wrong-value constant — we *never* vary it across
attempts. The goal is to map the defense, not log in.

This check is opt-in only. Enable via:
  - CLI:  --deep-throttle  (and optionally --deep-throttle-attempts N
                              and --deep-throttle-pacing SECONDS)
  - GUI:  the "Deep throttle mapping" checkbox + the attempts spinbox

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | No login throttling detected after ⟨attempts⟩ wrong-password attempts over ⟨total_elapsed⟩s | Install a login-throttling plugin (Wordfence Login Security, Limit Login Attempts Reloaded, iThemes Security). Add fail2ban with a wp-login.php pattern at the server level. Force 2FA on every administrator account. Once the plugin is configured, re-run this check to verify the threshold. |
| low/info | ⟨title⟩ | Partial result only — re-run with --deep-throttle and let it finish for a full picture, or with a smaller attempts count via --deep-throttle-attempts. |
| info | Deep throttle mapping skipped (opt-in) | No action needed. |
| info | Deep throttle mapping skipped: /wp-login.php not reachable | No action needed. |
| info | Login throttle threshold detected at attempt #⟨threshold_at⟩, ~⟨value⟩s into the test | No action needed — throttling is the defense working. |

## Evidence the check records

- Deep throttle mapping skipped (opt-in): Pass --deep-throttle on the CLI, or tick the GUI checkbox, to run this defense map. Current settings would run ⟨attempts⟩ attempts at ⟨pacing⟩s pacing (~⟨est_minutes⟩ min).
- Deep throttle mapping skipped: /wp-login.php not reachable: GET /wp-login.php -&gt; ⟨value⟩
- Login throttle threshold detected at attempt #⟨threshold_at⟩, ~⟨value⟩s into the test: Synthetic canary user: ⟨canary_user⟩ Fixed wrong password used every attempt (never varied). Throttle reason: ⟨threshold_reason⟩ Attempts: ⟨table⟩ Total elapsed: ⟨total_elapsed⟩s before throttle kicked in. This is the visible HTTP-layer defense. Network-layer (fail2ban, hosting provider) defenses may activate at different thresholds and can't be measured this way.
- No login throttling detected after ⟨attempts⟩ wrong-password attempts over ⟨total_elapsed⟩s: Synthetic canary user: ⟨canary_user⟩ Fixed wrong password used every attempt. All ⟨attempts⟩ attempts: ⟨table⟩ No 429/503, no captcha markers, no body-length anomalies. An online brute-force attack is feasible against this login surface.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Verify the threshold manually by repeating wrong-password attempts:
for i in {1..30}; do curl -s -X POST https://example.com/wp-login.php -d 'log=fakeuser&pwd=wrong' -o /dev/null -w '%{http_code} %{time_total}s\n'; sleep 10; done
```

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17
- **compliance_v2 / hitrust**: 01.r
- **compliance_v2 / cmmc**: AC.L2-3.1.8
- **compliance_v2 / nist_csf**: PR.AA-03
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.8.5

## Run only this check

```
wpsecscan only login_throttle_deep https://example.com
```

`only` runs this check alone and prints its findings.
