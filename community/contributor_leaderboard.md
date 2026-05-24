# Contributor leaderboard — design

Round-64 #128 — auto-generated CONTRIBUTORS.md, sorted by commits,
refreshed monthly via GitHub Action.

## Why a script, not GitHub's built-in graph

- We want a flat, copy-pasteable Markdown table in the repo
- We want categories (code / docs / triage) not just commits
- We want to credit issue-reporters too, not just PRs

## Format

```markdown
# Contributors

Thank you to everyone who has contributed to WPSecScan.

## Top 10 by commits (last 90 days)

| Rank | Contributor | Commits | Lines changed |
|------|-------------|---------|---------------|
| 1 | [@bryanflowers](https://github.com/bryanflowers) | 1042 | 28,491 |
| 2 | [@user-x](https://github.com/user-x) | 47 | 1,203 |
...

## Top 10 by issues filed (last 90 days)

| Rank | Reporter | Issues | Bugs (severity-high) |
|------|----------|--------|----------------------|
| 1 | [@user-y](https://github.com/user-y) | 12 | 3 |
...

## Top 10 by docs contributions

...

## All-time contributors (alphabetical)

[Generated from git shortlog]
```

## Generation

See `community/scripts/gen_contributors.py`. Run via:

```bash
python community/scripts/gen_contributors.py --since 90.days.ago
```

GitHub Action `community/contributor-leaderboard.yml` runs nightly,
opens a PR with the diff.

## Out of scope

- Real-time leaderboard (avoid leaderboard-driven gaming)
- Cash bounties for top contributors (already in BUG-BOUNTY.md
  separately)
