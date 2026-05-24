# Certified WPSecScan Auditor — program design

Round-64 #155 — entry-level cert for WP-security auditors using
WPSecScan.

## Why a cert?

Customers buying a "WordPress security audit" from a freelancer have
no good way to know the auditor actually knows what they're doing.
A cert gives a baseline signal + a small barrier to entry that
filters out the lowest-effort sellers.

## What the cert proves

The holder:
- Can run + interpret a full WPSecScan scan
- Knows which findings are real vs. false-positive in common
  hosting/plugin combinations
- Can write a remediation report that a non-engineer can action
- Understands the legal + ethical scope ("you own the site or have
  written permission")

## What it does NOT prove

- Pentesting beyond what WPSecScan does
- Custom exploit development
- Web app security in general

## Format

- Open-book online exam, 90 minutes
- 50 multiple-choice + 10 short-answer
- Pass: 70%
- Practical: produce a remediation report from a synthetic scan
  output (graded by community volunteers + Bryan)
- Re-cert annually (new threat landscape, new WP version)

## Curriculum (mirrors the MOOC)

1. Threat landscape
2. WP hardening
3. Plugin/theme audit
4. Auth
5. Network
6. REST/GraphQL
7. Backup/recovery
8. Monitoring + escalation

## Cost

- Exam: $0 (lab time costs us roughly $0)
- Re-cert: $0
- Optional printed certificate + mailed badge: $25 (covers postage)

## Ethics / scope statement

Every candidate signs:
```
I will only run WPSecScan against:
  - sites I own
  - sites I have written permission to test
  - sites in a bug-bounty program with explicit in-scope mention
I will not use the cert as authorisation for any other testing.
I will report findings responsibly per disclosure norms.
```

## Verification

Each cert is a Sigstore-signed JSON + a public verifier URL:
`https://wpsecscan.com/cert/<id>`. Employers can verify on the spot.

## Revocation

Revoked on: ethics violation, evidence of cheating, holder requests.
Revocation list public.

## Why not a paid cert (Offensive Security style)?

Because raising the floor matters more than gating it. Keep the
sustainability model elsewhere (sponsorships, enterprise feature
tier, donations).
