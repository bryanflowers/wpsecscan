# HUD (Heads-Up Display) — intentionally not implemented

## What ZAP's HUD does

OWASP ZAP ships a browser extension that overlays scan findings directly
on top of the page being tested. As the tester clicks around the site
manually, ZAP's findings for the current URL appear in a floating
sidebar, with click-to-investigate, click-to-fuzz, and click-to-replay
controls.

## Why we haven't implemented it

A HUD-equivalent requires either:

1. **A WebExtension** (Chrome / Firefox / Edge) — JavaScript codebase, a
   separate distribution channel (Chrome Web Store, Firefox Add-ons),
   per-browser packaging, and per-browser-update maintenance overhead.
   Doable but ~3 months of work for a single-maintainer project.

2. **A Burp Suite extension** — Kotlin / Jython, requires Burp Pro
   licence, ties WPSecScan to Burp's UI lifecycle.

3. **A man-in-the-middle proxy** that injects the HUD overlay JS into
   every response — privacy implications + breaks any site using strict
   CSP / certificate pinning.

For a defensive WordPress scanner aimed at site owners (not pentesters
doing live manual testing), the value/cost ratio is low. We deliver
similar value via the live console dashboard, the GUI's activity tab,
and the standalone HTML diff viewer — all of which let you see findings
without an in-browser overlay.

## If you really want it

Open an issue at https://github.com/bryanflowers/wpsecscan/issues with
your use case. If there's enough demand we'll add a WebExtension to the
roadmap.

## Alternatives that work today

- **Live console dashboard** (`wpsecscan --demo` to see) — shows findings
  + activity feed in real time
- **GUI Activity tab** — same content but in a window
- **Diff viewer** (`Tools → Two-report HTML diff viewer`) — compare two
  scans side-by-side
- **Exploit playbook walker** (right-click any finding) — steps through
  curl / sqlmap / Metasploit / nuclei / wpscan commands for that finding
