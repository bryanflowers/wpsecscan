# Login timing side-channel (user enum)

**check_id**: `login_timing`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.002 — Gather Victim Identity Information: Email Addresses

## What it does

Login timing side-channel — username enumeration via response timing.

WordPress's wp-login.php often returns DIFFERENT response times depending on
whether the username exists:
  - User exists, password wrong  → bcrypt hash comparison runs (~300+ ms)
  - User doesn't exist           → fast bail (~50-100 ms)

That delta lets an attacker prune their brute-force list to only valid users.

Probe: send 5 wrong-password attempts for `admin` (likely valid) and 5 for a
random synthetic username (definitely invalid). Compare medians. Flag ≥40%
delta as a username-enumeration vector.

Passive (no real password guesses, just timing).

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.5.15
- **compliance_v2 / hitrust**: 01.r
- **compliance_v2 / cmmc**: IA.L1-3.5.1
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan --target https://example.com --only login_timing
```
