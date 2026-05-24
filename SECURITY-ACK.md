# Security researcher acknowledgments

Thanks to everyone who has responsibly disclosed security issues in
WPSecScan. This page is updated when patches ship.

## Hall of fame

_(none yet — first responsible disclosure earns this slot)_

## How to get listed

1. Find a real vulnerability in WPSecScan (the scanner itself, not in
   plugins/themes we scan)
2. Report it per [SECURITY.md](SECURITY.md) — email
   bryaninbangkok@gmail.com with "WPSecScan security disclosure" in the
   subject
3. Wait for our acknowledgment + patch (target: 7 days first-response,
   30 days patch)
4. Once the fix ships, we add your name + the CVE here

We'll honour any pseudonym you prefer + optional link to your blog /
Twitter / etc. Add a `WPSecScan-Researcher-Display-Name:` line to your
disclosure email if you want something other than your sender name.

## Scope

In scope:
- The `wpsecscan` Python package and its CLI / GUI binaries
- The `wpsecscan-companion` WordPress plugin
- The `data-feed` branch aggregator output
- `scripts/aggregate-cve-feed.py`
- Build / release / signing infrastructure
- The licensing system

Out of scope:
- Findings in plugins/themes WPSecScan scans (report to the upstream
  plugin author or Patchstack instead)
- Denial-of-service via unreasonable input sizes (Python's stdlib
  limitations are out of scope)
- Issues only reproducible against modified WPSecScan builds
- Social engineering of the maintainer
- Physical attacks
