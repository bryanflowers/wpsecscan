# WPSecScan browser-extension launcher

Right-click any page → "Scan with WPSecScan" → POSTs the URL to your local
WPSecScan API server.

## Install (developer mode)

### Chrome / Edge
1. `chrome://extensions/` → enable Developer Mode → "Load unpacked"
2. Pick this directory

### Firefox
1. `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on..."
2. Pick `manifest.json`

## Prereq: run the WPSecScan API server

```
wpsecscan api-server --listen 127.0.0.1:8765
```

The server is local-only by default. Set `--api-token` in production.

## Customisation

Click the extension icon → Options → set a different API URL if the
server runs elsewhere (e.g. a Docker container at `:9000`).
