# State of WordPress Security 2026 — annual report outline

Round-64 #157 — outline for the inaugural annual report. Publish each
December covering the year just ended.

## Audience

- WP agency owners (budget allocation)
- Security press (data they can cite)
- Hosting providers (validation of investments)
- WP community (collective situational awareness)

## Sources (all opt-in)

- WPSecScan aggregator data (anonymous)
- Submitted public-scan DB (anonymous; round-64 #123)
- Public CVE databases (NVD, GHSA, WPVulnerability)
- Wordfence/Patchstack/MainWP public summaries
- Hosting-provider published incident counts (when available)

## Sections

### 1. Executive summary (1 page)
- Top 5 numbers that matter
- "Are we more or less secure than last year?"

### 2. The threat year in review (4 pages)
- Top 10 exploited CVEs (in-the-wild)
- Notable incidents (named where public)
- Trend lines (cryptominer vs Magecart vs SEO-spam)

### 3. Plugin ecosystem (3 pages)
- Top 10 plugins by CVE count
- Average time-to-patch (vendor → patch availability)
- Average time-to-install (patch available → installed median)
- Pirated-plugin prevalence (estimated)

### 4. WordPress core (1 page)
- Adoption of latest major release at year-end
- Core CVEs disclosed
- Time-to-update

### 5. Hosting + infrastructure (2 pages)
- TLS adoption (TLS 1.3 percentage)
- HTTP/3 + post-quantum readiness
- WAF coverage
- MFA on admin accounts (estimated)

### 6. Compliance + governance (2 pages)
- PCI 4.0 adoption (for WooCommerce sites)
- GDPR cookie-consent honest-implementation rate
- Bug-bounty program coverage

### 7. Looking ahead (2 pages)
- 2026's emerging risks (AI/LLM injection, Web3, supply chain)
- WPSecScan's roadmap response
- What the community needs

### 8. Methodology (1 page)
- Data sources
- Sample sizes
- Limitations + biases

### 9. Acknowledgements + how to contribute next year

## Distribution

- Free PDF on wpsecscan.com/state-of-wp-2026
- HTML web version (CC-BY-SA)
- Press kit with high-res charts
- Talk circuit at WordCamp + DEF CON + RSA recap

## Charts to produce

- Top 10 CVEs (bar)
- Time-to-patch distribution (histogram)
- TLS version adoption over year (line)
- MFA adoption by role (stacked bar)
- Incident type breakdown (pie)
- WPSecScan check fire-frequency top 20 (bar)
