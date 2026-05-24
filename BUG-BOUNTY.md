# Bug bounty program — WPSecScan

Round-64 #38: bug bounty for WPSecScan itself. **Self-funded by the
maintainer**; bounties are paid in cash via GitHub Sponsors / Stripe /
crypto at the reporter's choice.

## Bounties (current as of v2.2.0)

| Severity | Examples | Bounty |
|----------|----------|--------|
| **Critical** | RCE in companion plugin (POSTable from internet); arbitrary file read via the scanner; license-key forge; supply-chain compromise of the data-feed branch | **$500** |
| **High** | Stored XSS in admin dashboard; SQLi in companion plugin; auth bypass on companion REST endpoint; aggregator script eats arbitrary files | **$200** |
| **Medium** | CSRF on companion admin form; reflected XSS in HTML report; path traversal in `wpsecscan db source-stats` | **$50** |
| **Low** | Information disclosure (non-secrets); rate-limit bypass; missing security header | **$10 or a t-shirt** |

Bounties paid only on first valid report per finding. Patch must ship
before payment. Public disclosure embargo: 90 days from report (or
day-of-patch, whichever sooner).

## How to submit

1. Email `bryaninbangkok@gmail.com` with subject line starting `[WPSecScan bug bounty]`
2. Include:
   - Reproduction steps (the smallest PoC that demonstrates the bug)
   - Affected version (`wpsecscan --version`)
   - Your proposed severity (we'll discuss if different)
   - Your preferred payment method
3. Wait for our acknowledgment (target: within 7 days)
4. Coordinate disclosure timeline

## Scope

In scope (same as SECURITY-ACK.md):
- The `wpsecscan` Python package and its CLI / GUI binaries
- The `wpsecscan-companion` WordPress plugin
- The `data-feed` branch aggregator output  
- Build / release / signing infrastructure
- The licensing system

Out of scope:
- Vulnerabilities in third-party plugins/themes WPSecScan scans
  (report to the upstream author or Patchstack)
- Issues in our docs / website that don't expose user data
- DoS-via-resource-exhaustion (Python has limits we can't fix)
- Anything requiring physical access or social engineering

## Why we run this

WPSecScan is a defensive security tool. If we have vulns we're hypocrites.
A small bounty pool keeps us honest. Reports are also added to our
[SECURITY-ACK.md](SECURITY-ACK.md) hall of fame.
