# WPSecScan browser overlay

Highlights wp-admin pages with the findings from your most recent WPSecScan
run. Tight feedback loop while you fix things — you stop alt-tabbing
between the report and the wp-admin tab.

## Chrome / Edge (Manifest V3)

1. `wpsecscan https://your-site --json-only` (saves to `~/.wpsecscan/reports/`).
2. `chrome://extensions/` → **Developer mode** → **Load unpacked** →
   choose `browser-extension/chrome`.
3. Open `https://your-site/wp-admin/`.
4. Click the WPSecScan icon → pick the JSON report → reload wp-admin.

A floating pill in the bottom-right shows "WPSecScan: N issues (worst: …)".
Click it to expand a panel listing the findings that match the page URL.

## Firefox

`about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** →
choose `browser-extension/firefox/manifest.json`. Same flow as Chrome.
The Firefox manifest is MV2 (Firefox's MV3 is not yet fully stable for
content scripts); functionally identical.

## Edge

Edge uses Chrome's MV3 manifest unmodified — load the `chrome/` folder.

## How URL-matching works

Each finding can carry a `url` field (the specific URL that triggered
the finding). The content script considers a finding "on this page" if:

* the page URL starts with `finding.url`, OR
* `finding.url` starts with the page URL, OR
* the page's pathname is a substring of `finding.url`.

This handles the three common cases — findings on a specific admin page,
findings on the root that should appear everywhere, and findings keyed
to a query-string-bearing URL.
