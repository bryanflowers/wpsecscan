# WPSecScan CTF — Round 1

Round-64 #153 — first community CTF challenge.

## Scenario

You're auditing `https://ctf-target-round1.wpsecscan.com` (a
deliberately-vulnerable WordPress site we host). Your job: use
WPSecScan to find 5 specific flags, each a string of the form
`WPSEC{<hex>}` embedded in a finding's evidence field.

## Rules

- Use only WPSecScan + read-only tools (no exploit attempts beyond
  what WPSecScan does)
- Submit flags via PR to `education/ctf/round1-solutions.md` (we'll
  delete the file before judging)
- Top 10 fastest valid submissions get listed in `SECURITY-ACK.md`
- Top 3 get a t-shirt + WPSecScan stickers

## Hints (in increasing spoiler-ness)

### Hint 1 — Where to start
Run `wpsecscan scan https://ctf-target-round1.wpsecscan.com --aggressive`.
The flag locations span both passive + aggressive checks.

### Hint 2 — File paths
At least 2 flags are in files exposed under `/wp-content/` paths the
default WP install would never expose.

### Hint 3 — REST routes
At least 1 flag is in a REST endpoint that requires no auth but is
buried under a non-obvious path. Try `wpsecscan db source-stats` to
see which checks fire on REST routes.

### Hint 4 — Embedded JS
One flag is hidden inside a `/* */` comment in built CSS. Look at the
`tailwind_css_comment_leak` check output.

### Hint 5 — DB layer
One flag is only reachable via the companion plugin endpoint (the
target ships a vulnerable companion). Install the companion locally
first or read the `db_trigger_audit` check.

## Deadline

First Sunday of the month following this CTF release.

## Future rounds

Round 2: Magento/WooCommerce-focused. Round 3: headless WP. Subscribe
to GitHub Discussions for announcements.
