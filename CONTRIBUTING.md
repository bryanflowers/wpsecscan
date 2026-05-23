# Contributing to WPSecScan

Thanks for your interest in contributing. This document covers the basics:
how to set up locally, what we accept, and the no-surprise rules for new
checks.

## Quick start (local dev)

```bash
git clone https://github.com/bryanflowers/wpsecscan
cd wpsecscan
python -m venv .venv
. .venv/bin/activate         # Linux / Mac
# .venv\Scripts\Activate.ps1  # Windows PowerShell
pip install -r requirements.txt
pip install pytest

pytest -q                    # should report 358+ passing
python run.py --demo         # see every feature working
python run_gui.py            # GUI
```

Tests are mandatory for every PR. If you add a check, add a happy-path
test in `tests/test_round_<latest>.py` or a new file.

## What we accept

✅ **Yes:**
- New defensive checks for WordPress (CVE matching, misconfiguration
  detection, fingerprinting)
- New reporters (export formats, dashboards, CI integrations)
- Bug fixes, perf improvements, test coverage
- Doc / translation contributions
- New integrations with public threat-intel feeds (CISA KEV, EPSS,
  VirusTotal, OTX, etc.) — must be opt-in via a token flag
- New GUI windows, themes, language packs

❌ **No:**
- **Online password brute-force.** Period. The deep-throttle check
  measures rate-limits with a synthetic non-existent user and a fixed
  wrong password — never actual credential guessing.
- **Auto-exploitation** beyond proof-of-concept marker payloads. The
  exploit playbook prints commands; the scanner does not execute them.
- **Bypasses for detection** (timing evasion designed to slip past
  intrusion-detection systems on third-party infrastructure). WPSecScan
  is for sites you own; if you need to evade detection, you don't have
  authorisation.
- **Mass targeting** beyond multi-target file mode. No worm-style spread,
  no auto-discovery of "all WordPress sites in /16".
- **Supply-chain attacks.** Self-explanatory.

If you're unsure, **open a discussion or draft PR first** before doing the
work — easier to redirect early.

## New-check checklist

If you're adding a check at `wpsecscan/checks/<id>.py`:

- [ ] Module exports `async def check(client, ctx) -> list[Finding]`
- [ ] Every `Finding(severity=...)` uses one of: `info|low|medium|high|critical`
- [ ] Aggressive checks gate on `ctx.get("aggressive")` and short-circuit
      with an `info` finding when off
- [ ] Checks that need a token gate on `ctx.get("<token_name>")` and emit
      an info-level "skipped (no token)" finding when missing
- [ ] Registered in `wpsecscan/checks/__init__.py` ALL_CHECKS with the
      correct `aggressive` flag
- [ ] Tag entry added to `wpsecscan/data/check_tags.json` with `owasp`,
      `attack`, `cwe`, `d3fend` fields
- [ ] Compliance entry added to `wpsecscan/data/compliance_map.json`
- [ ] Reference URLs added to `wpsecscan/data/references.json`
- [ ] Test in `tests/test_round_*.py` covering at least the happy-path
      response and the skip path (if gated)
- [ ] If the check does meaningful work an end user should SEE happen,
      emit one `activity.emit("category", "...")` event at the
      definitive-success point (see [activity.py](wpsecscan/activity.py))

## Pull-request process

1. Fork + branch off `main`. Branch name: `feat/<short-slug>` or `fix/<short-slug>`.
2. Run `pytest -q` locally — must pass green.
3. Open the PR; the GitHub Actions tests workflow re-runs the suite.
4. CODEOWNERS auto-requests review for any change to active-payload
   checks (`sqli.py`, `default_creds.py`, `path_traversal.py`, etc.).
5. We aim to triage within 7 days. If you don't hear back, ping by
   commenting `@bryanflowers ping`.

## Commit style

- Short imperative subject (`add cloudfront fingerprint check`)
- Wrap body at 72 chars
- Reference issues with `Fixes #123`
- One logical change per commit; squash trivial fixups before review

## Code style

- 4-space indent, no trailing whitespace
- Type hints everywhere except trivial helpers
- Prefer `pathlib.Path` over `os.path`
- Async checks must respect `is_cancelled` if scanner exposes it (it does)
- No bare `except:` — use `except Exception` with `# noqa: BLE001` only if
  you really need to swallow everything
- Wide try/except around imports is OK (`try: from .X import Y; except ImportError: ...`)

## Releases

Maintainers only. See `scripts/release.ps1`.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be
nice. Report violations to bryaninbangkok@gmail.com.

## Security issues

Report privately — see [SECURITY.md](SECURITY.md). Do not open a public
issue.
