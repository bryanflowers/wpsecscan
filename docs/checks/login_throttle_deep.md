# Deep throttle mapping (opt-in, 20 min)

**check_id**: `login_throttle_deep`
**aggressive**: no
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
wpsecscan --target https://example.com --only login_throttle_deep
```
