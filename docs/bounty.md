# Bug-bounty workflow

WPSecScan ships submission-template builders for HackerOne, Bugcrowd,
Intigriti, Patchstack, wp.org plugin team, and CVE Numbering Authorities.

## OSINT: is there a bounty?

```
wpsecscan --target https://example.com --osint-bounty
```

Probes HackerOne / Bugcrowd / Intigriti for an active program. Results
cached 24h in `~/.wpsecscan/bounty_cache.json` so batch scans don't
hammer the platforms.

## Generate a submission

```
wpsecscan submit --report report.json --finding-id F-0042 --platform hackerone
```

Outputs a markdown template ready to paste into the HackerOne form, with:
- Title (auto-pulled from finding)
- Summary
- Steps to reproduce (URL + payload)
- Impact (severity-mapped)
- Suggested remediation
- WPSecScan reference (links to the check's doc page)

Supported `--platform`: `hackerone`, `bugcrowd`, `intigriti`, `patchstack`,
`wporg`, `cve`.

## Bundle export

To shop a finding to multiple channels at once:

```
wpsecscan submit --report report.json --finding-id F-0042 --bundle out.json
```

Writes a JSON with all 4-5 channel payloads pre-filled. Use for one-click
multi-channel disclosure.

## CVE record (5.1 schema)

```
wpsecscan submit --report report.json --finding-id F-0042 --platform cve \
                  --vendor Acme --product FooPlugin \
                  --versions 1.0,1.1,1.2 > cve.json
```

Outputs a CVE 5.1 record. Submit at
[cveform.mitre.org](https://cveform.mitre.org/) or your CNA's intake.

## Risk-aging

Findings older than 30 days auto-escalate by one severity level (the
`risk_aging.py` module). Use this to spot which findings keep slipping
on your priority list.

## Coordinated-disclosure email

```
wpsecscan disclose --report report.json --finding-id F-0042 \
                    --vendor Acme --email security@acme.com
```

Drops a polite 90-day-disclosure email body into your clipboard.
