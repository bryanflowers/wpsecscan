---
id: cloudflare_origin_leak
title: "Cloudflare origin-IP leak via crt.sh + DNS history"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 379
---

# Cloudflare origin-IP leak via crt.sh + DNS history

**check_id**: `cloudflare_origin_leak`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — Gather Victim Network: IP Addresses
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Item #2 — Cloudflare origin-IP leak.

When a site is fronted by Cloudflare, the public-facing IP belongs to CF.
But CF only protects what you point through it: leak the origin's true IP
and an attacker can bypass the WAF entirely by hitting it directly with a
spoofed Host header.

This check looks for three common leaks:

1. **Certificate transparency logs (crt.sh)** — leaf certs issued for
   subdomains the user forgot to proxy (mail., direct., staging.) often
   point straight at the origin. We pull the leaf set, A-resolve each
   non-CF subdomain and report any that's NOT in a Cloudflare range.

2. **DNS A records of common bypass subdomains** — `direct.`, `origin.`,
   `cpanel.`, `webdisk.`, `ftp.`, `mail.`, `webmail.`, `pop.`, `smtp.`,
   `ns1.`, `staging.`, `dev.`, `test.` are routinely set to the origin
   IP and forgotten about.

3. **MX records** — mail servers run on the origin host frequently.
   Reverse-resolving the MX target into an A record often leaks the
   real IP.

Findings are medium-severity (recon-stage; weaponising requires the
attacker to discover and probe directly) and include the suggested fix
of either proxying everything or moving non-web services to a separate
host that doesn't share infra with the WP site.

Uses only **free** sources: crt.sh (no key) + the system DNS resolver.
No paid Censys / Shodan integration in this iteration.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Cloudflare origin IP may be leaked via MX records | Host mail on a separate server (Fastmail / Google Workspace / Mailgun) so the MX target doesn't double as the WP origin. If you must self-host mail on the same box, restrict :443 to Cloudflare's IP ranges at the firewall. |
| medium | Cloudflare origin IP may be leaked via ⟨count⟩ non-proxied subdomain(s) | 1. For each non-proxied subdomain above, either: a. proxy through Cloudflare (orange-cloud the DNS record), OR b. move the service to a separate host that does NOT also serve the WP origin. 2. Rotate the origin server's IP after sealing the leak (CF Authenticated Origin Pulls + restrictive ufw/security-group rules so only CF IPs reach :443). |
| info | Cloudflare origin-IP leak skipped — host did not resolve | No action. |
| info | Cloudflare origin-IP leak skipped — site is not behind Cloudflare | No action. |
| info | No Cloudflare origin-IP leak detected | No action needed. |

## Evidence the check records

- Cloudflare origin-IP leak skipped — host did not resolve: socket.getaddrinfo(⟨host⟩) returned no A records.
- Cloudflare origin-IP leak skipped — site is not behind Cloudflare: Apex ⟨host⟩ resolves to ⟨value⟩; none of those addresses are in a published Cloudflare range.
- Cloudflare origin IP may be leaked via ⟨count⟩ non-proxied subdomain(s): The apex (⟨host⟩) is served via Cloudflare, but the following subdomains resolve directly to IPs outside Cloudflare's published ranges. An attacker can bypass the WAF by sending HTTP requests with `Host: ⟨host⟩` to those IPs: ⟨value⟩
- Cloudflare origin IP may be leaked via MX records: Mail servers for ⟨apex⟩ resolve to non-Cloudflare IPs: ⟨value⟩ If mail is hosted on the same machine as the WP origin (shared cPanel / Plesk / single-VPS deployments), the MX IP IS the origin and CF protection is bypassable.
- No Cloudflare origin-IP leak detected: Checked ⟨count⟩ candidate subdomain(s) (from crt.sh + common bypass prefixes) + MX records. None resolved outside Cloudflare's published IP ranges.

## Compliance mapping

- **compliance_map / pci_dss**: 1.3.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## References

- https://crt.sh/?q=%25

## Run only this check

```
wpsecscan only cloudflare_origin_leak https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
