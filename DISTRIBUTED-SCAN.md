# G4 — Distributed scanning

WPSecScan's supported pattern for scanning many sites in parallel is the
existing **multi-target** flow. The plan to ship a Redis-backed worker
coordinator was descoped — the multi-target pattern covers the use cases
that motivated it, without adding a new daemon to operate.

## Patterns

### 1. Multi-target file (single host)

```
wpsecscan --file targets.txt --concurrency 20 --out reports/
```

- One line per URL in `targets.txt` (blank lines + `#` comments ignored).
- Each target gets its own JSON / HTML report under the output directory.
- The dashboard report (`--dashboard`) consolidates risk scores across
  every target into one HTML page.
- For 100+ targets, increase `--concurrency` and add `--quiet` so the
  console doesn't become the bottleneck.

### 2. Sharded multi-host (true parallel)

Split the target list across N hosts and run multi-target on each:

```
# host A
wpsecscan --file targets.shard-1-of-4.txt --out reports/

# host B
wpsecscan --file targets.shard-2-of-4.txt --out reports/

# etc
```

Then `rsync` every host's `reports/` into one place and run the dashboard
reporter against the combined directory.

### 3. GitHub Actions matrix (no infra)

For free distributed scanning, use a GitHub Actions matrix job (see
`.github/workflows/wpsecscan.yml`):

```yaml
strategy:
  matrix:
    shard: [1, 2, 3, 4]
steps:
  - run: wpsecscan --file targets.shard-${{ matrix.shard }}.txt --out reports/
  - uses: actions/upload-artifact@v4
    with: { name: reports-${{ matrix.shard }}, path: reports/ }
```

A second job downloads all shard artifacts and runs the dashboard
reporter on the combined directory.

### 4. Daemon mode (--daemon CONFIG.yml)

For recurring scans (nightly / weekly), use `--daemon` with a YAML config
listing targets + cron expressions. It's a single host but handles the
scheduling. See `docs/daemon-config-example.yml`.

## Why no Redis worker pool

The Redis pattern was attractive on paper but adds:

- A new infrastructure component to operate (Redis itself).
- A worker daemon process with its own crash / restart story.
- A shared-state race condition surface (job claims, retries).

For ≤500 targets, multi-target + a beefy host is faster and simpler than
distributing. For 500+ targets, the Actions matrix pattern is free,
zero-infra, and outperforms a single Redis pool. The simpler patterns
above cover both extremes with no new moving parts.
