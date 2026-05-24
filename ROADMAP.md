# WPSecScan public roadmap

Round-64 #126 — last updated 2026-05-24 for v2.2.0 release.

## Shipped

- **v2.2.0** (2026-05-24) — Round-64: 165 features across active
  exploit verification, continuous monitors, threat intelligence,
  trust signals, Web3/NFT/payment checks, enterprise scaffolds, etc.
- **v2.1.0** (2026-05-23) — 8-source nightly CVE aggregator
- **v2.0.0** (2026-05-20) — AGPLv3 + WP companion plugin + 15
  compliance frameworks

## In progress (next 30 days — v2.3.0)

- AI-assisted triage (Group C, deferred from round-64)
- Real third-party security audit kickoff (RFI to PFI firms)
- OpenSSF Scorecard score targeting > 7.0
- pip release on PyPI with Sigstore signatures (PEP 740)

## Q3 2026 (v2.4.0)

- React Native mobile clients (Round-64 #98 scaffold → real apps)
- Kubernetes operator implementation (Round-64 #106 scaffold → real)
- Distributed coordinator across N workers (Round-64 #160)
- Spanish + German GUI localisation completion

## Q4 2026 (v3.0.0)

- EV code-signing certificate (Round-64 #31)
- E&O insurance program (Round-64 #40)
- Third-party audit report published
- Annual State of WP Security report v1

## How to influence the roadmap

- GitHub Discussions: <https://github.com/bryanflowers/wpsecscan/discussions>
- "Request a check" voting page (Round-64 #130)
- Discord: TBD
- Direct email: bryaninbangkok@gmail.com

## Things we will NOT do

- Add telemetry that's not opt-in (PROMISE)
- Move to a paid-only model (the open-source scanner stays open)
- Accept code from PRs without unit tests (lowers quality bar)
- Add JS-runtime requirements to the .exe distribution (keeps Defender FP rate low)
