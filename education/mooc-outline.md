# WPSecScan MOOC — 8-module outline

Round-64 #154 — design for a free MOOC on WordPress security using
WPSecScan as the lab tool. Not yet recorded.

## Audience

WordPress admins + freelance developers who want a security-baseline
education. No prior security experience required.

## Format

8 modules × ~1h video + 45 min lab + 30 min quiz.

## Module 1 — The WordPress threat landscape (2026)

- Real attacker motivations (cryptominer, redirect-farm, SEO-spam)
- Top 10 incident types from public data
- Why WordPress, why so often
- Lab: scan example.com (yours), identify the top finding

## Module 2 — Hardening the install

- wp-config.php settings every site should have
- Disable file editing, restrict PHP execution
- Salt rotation
- Lab: apply each setting to a fresh install, re-scan

## Module 3 — Plugins + themes

- The plugin trust model (or lack thereof)
- Nulled / pirated plugins as malware delivery
- Subscribing to security advisories
- Lab: audit a real plugin you use with WPSecScan plugin_specific_audit

## Module 4 — Authentication

- Why MFA is non-negotiable
- App passwords, JWTs, OAuth
- Brute-force defence (Cloudflare, fail2ban, wp-cli)
- Lab: enable MFA on every admin account

## Module 5 — Network layer

- TLS settings (HSTS, OCSP stapling, modern ciphers)
- CSP, SRI, COOP/COEP
- WAF + CDN selection
- Lab: get an A+ on SSL Labs + the WPSecScan TLS check

## Module 6 — REST API + GraphQL

- Surface area mapping
- Permission callbacks
- Rate limiting
- Lab: probe your own /wp-json/ surface; close the unintended endpoints

## Module 7 — Backup + recovery

- Backup hygiene
- "Trust nothing" restore process
- Audit log for forensics
- Lab: trigger a known-good backup, verify restore on a staging copy

## Module 8 — Continuous monitoring

- Setting up WPSecScan daemon mode
- Slack/Discord/PagerDuty integration
- Quarterly internal audit
- Lab: subscribe to a CVE feed, get a slack ping on a real (small) issue

## Certification

- 70% on cumulative quiz → digital badge (CC-BY-SA verifiable PDF)
- Optional capstone: contribute a check or doc PR

## Hosting

- YouTube playlist (Creative Commons BY-SA)
- Mirror on Internet Archive
- Captions in en/es/de/fr/ja/zh

## Cost to learner

$0. Sponsored by WPSecScan project. Donations accepted.
