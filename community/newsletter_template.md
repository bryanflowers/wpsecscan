# WPSecScan monthly threat-intel newsletter — template

Round-64 #127 — copy this template each month, fill the placeholders,
publish to the mailing list + GitHub Discussions.

---

## WPSecScan Threat Intel — {{MONTH YEAR}}

### Headline

{{One-sentence summary of the most important thing this month.}}

### Top 5 new CVEs in our database

1. **CVE-{{ID}}** — {{plugin}} {{version}} — {{severity}}
   - What an attacker can do: {{1 line}}
   - Affected install base estimate: {{N k}}
2. ...
3. ...
4. ...
5. ...

### Aggregated DB delta

- Total vulns added this month: {{N}}
- Critical: {{N}}, High: {{N}}, Medium: {{N}}
- By source: NVD {{N}}, WPVulnerability {{N}}, GHSA {{N}}, etc.

### Top exploit-in-the-wild

{{ATT&CK technique or specific exploit}} — what we've seen, what to
block, what WPSecScan check fires on it.

### New checks shipped this month

- check_id_1 — what it catches
- check_id_2 — what it catches

### Project news

- Releases: {{vX.Y.Z, vX.Y+1.Z, ...}}
- Tests passing: {{N}} (+{{delta}})
- Contributors: {{N}} new, total {{N}}
- Top community contributor: {{@github_handle}}

### What to do this week

If you're an admin:
1. Update plugins to {{list}}
2. Run `wpsecscan db update && wpsecscan scan <site>`
3. Review the {{N}} new findings

If you're a dev:
1. Add {{security pattern}} to your CI
2. Subscribe to {{CVE feed}} for {{your stack}}

### Subscribe

<https://github.com/bryanflowers/wpsecscan/discussions/categories/announcements>
