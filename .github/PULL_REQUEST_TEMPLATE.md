<!-- Thanks for the PR. Please fill in the blanks; CI runs the test suite. -->

## What this PR does

<!-- One paragraph. The user-visible change, not the implementation. -->

## Why

<!-- Link the issue or describe the motivation. -->

Fixes #

## How I tested

<!-- Be specific. "Ran pytest" is fine for a small fix; a new check needs
     more. -->

- [ ] `pytest -q` passes locally
- [ ] Manually ran the affected code path (describe how)
- [ ] Added / updated tests in `tests/`

## Authorisation check

<!-- Only relevant for PRs that test against a real website. -->

- [ ] N/A — pure code change, no live scan
- [ ] I scanned only sites I own or have written permission to test

## Type of change

- [ ] Bug fix
- [ ] New check (please confirm CONTRIBUTING.md "what we accept" applies)
- [ ] New reporter / integration / GUI feature
- [ ] Documentation
- [ ] Refactor / perf

## New-check checklist (delete if N/A)

- [ ] Severity values are all in `info|low|medium|high|critical`
- [ ] Aggressive checks gate on `ctx.get("aggressive")`
- [ ] Token-gated checks emit an info "skipped (no token)" finding
- [ ] Registered in `wpsecscan/checks/__init__.py` `ALL_CHECKS`
- [ ] Tag + compliance entries added to `data/check_tags.json` + `data/compliance_map.json`
- [ ] Reference URLs in `data/references.json`
- [ ] At least one `activity.emit(...)` if the check does visible work

## Breaking changes

<!-- Anything that changes a CLI flag, JSON schema, file location, or
     the GUI's external API. Bump the major version if so. -->

- [ ] None
- [ ] Yes — described below:
