# Security policy

## Reporting a vulnerability in WPSecScan itself

If you find a security issue **in the scanner** (path traversal in the API
server, RCE in a custom-plugin loader, credential leak in the audit-log,
etc.), please **do not** open a public GitHub issue.

**Where to report:** email **bryaninbangkok@gmail.com** with the subject
line `WPSecScan security report` and as much detail as you'd put in a
public CVE writeup — repro steps, affected version, attack scenario,
suggested fix if you have one.

You can also use **GitHub Security Advisories** (the "Report a
vulnerability" button under the repo's *Security* tab) — that creates a
private channel between you and the maintainers.

## What to expect

| Step | Timeline | What happens |
|------|----------|--------------|
| Initial reply | within 5 business days | Confirmation that the report arrived + first triage |
| Severity assessment | within 14 days | We classify as low / medium / high / critical and assign CVSS if applicable |
| Patch | within 30 days for high/critical | Fix lands on `main`; CVE requested for critical issues |
| Public disclosure | coordinated | We'll credit you in the release notes unless you ask to be anonymous |

We follow **90-day coordinated disclosure**: if we can't fix within 90
days, we'll discuss extension with you.

## Scope

**In scope:**
- Code execution / path traversal / credential disclosure in WPSecScan
  itself (CLI, GUI, API server, daemon, reporters)
- Any check that probes the network outside the user's declared target
- Token / secret leakage in saved JSON reports or the audit log
- Dependency vulnerabilities in pinned wheels (see `wpsecscan --sbom`)

**Out of scope:**
- Bugs in the websites WPSecScan scans (those are findings, not security
  issues in the scanner)
- Defender / SmartScreen false positives — see `CODE-SIGNING.md`
- Issues that require physical access to the user's machine

## Hall of fame

Reporters are credited in the release notes. We do not currently offer a
bug bounty — this is an open-source project maintained on volunteer time.

## Reporting issues that AREN'T security-sensitive

For functional bugs, feature requests, or general questions, please open
a regular GitHub issue. See [CONTRIBUTING.md](CONTRIBUTING.md).
