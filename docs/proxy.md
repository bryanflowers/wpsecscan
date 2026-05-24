# Proxy support

WPSecScan supports outbound proxies for every scanner HTTP/HTTPS request:

- HTTP proxy: `http://proxy.example:8080`
- HTTPS proxy: `https://proxy.example:8443`
- SOCKS5 (e.g. Tor): `socks5://127.0.0.1:9050`

## CLI

```bash
# Single scan via SOCKS5 (e.g. local Tor):
wpsecscan --target https://example.com --proxy socks5://127.0.0.1:9050

# HTTP proxy with auth (password URL-encoded automatically):
wpsecscan --target https://example.com \
          --proxy http://proxy.example:8080 \
          --proxy-auth alice:s3cret
```

For SOCKS5 you need the optional socksio dep:

```bash
pip install 'httpx[socks]'      # adds socksio
```

For the .exe builds this is bundled.

## Environment variables (auto-detected)

These are read **without** a flag:

| Var | Purpose |
|-----|---------|
| `WPSECSCAN_PROXY_URL` | Same as `--proxy` |
| `WPSECSCAN_PROXY_AUTH` | Same as `--proxy-auth` (`user:pass`) |
| `HTTP_PROXY` | httpx auto-detects |
| `HTTPS_PROXY` | httpx auto-detects |
| `ALL_PROXY` | httpx auto-detects |
| `NO_PROXY` | httpx auto-detects (comma-separated hostnames) |

Resolution order: explicit `--proxy` → `WPSECSCAN_PROXY_URL` → standard
proxy env vars.

## Per-site proxy (multi-site dashboard)

Different sites can use different proxies:

```bash
# Site A scanned via Tor:
wpsecscan sites add https://a.example --weekly \
          --proxy socks5://127.0.0.1:9050

# Site B scanned via corporate HTTP proxy:
wpsecscan sites add https://b.example --weekly \
          --proxy http://corp-proxy:3128 \
          --proxy-auth alice:s3cret

# Site C scanned direct (no --proxy):
wpsecscan sites add https://c.example --weekly
```

Each site's proxy lives in `~/.wpsecscan/sites.json`. The proxy-auth
password is **sealed at rest** (DPAPI on Windows, TPM2/gpg elsewhere
when `hardware_keys` module dependencies are installed).

## Verifying the proxy is in use

```bash
# If you're using Tor specifically:
wpsecscan --target https://check.torproject.org --proxy socks5://127.0.0.1:9050

# Look for the "Congratulations. This browser is configured to use Tor."
# string in the report — confirms routing through an exit node.
```

Or use Python directly:

```python
from wpsecscan.integrations.tor_proxy import check_tor_exit
import os
os.environ["WPSECSCAN_PROXY_URL"] = "socks5://127.0.0.1:9050"
print(check_tor_exit())   # {'ok': True, 'ip': '...', 'is_tor': True}
```

## GUI

GUI users: **Tools → Settings → Proxy** (round-61+).
- URL field, optional user/password
- "Test connection" button uses `tor_proxy.check_tor_exit()` — shows
  your apparent public IP (works for any proxy, not just Tor)

## Common gotchas

- **`ImportError: socksio`** — install `httpx[socks]` (or the bundled
  .exe, which already includes it)
- **Tor browser's port (9150)** vs **Tor daemon's port (9050)** —
  the browser bundle runs SOCKS on `127.0.0.1:9150`; the standalone
  daemon defaults to `127.0.0.1:9050`. Easy to confuse.
- **Corporate proxies stripping HTTPS** — many corporate MITM proxies
  re-sign certificates. The scanner will fail TLS verification unless
  you also pass `--insecure` (use with care — it disables cert
  checking entirely).
- **Slow scans** — proxies add latency. Drop `--concurrency` from the
  default 10 to 3-4 over a slow proxy.

## Privacy note

The scanner connects to several public-internet endpoints in addition
to your target:

- Wordfence Intelligence (CVE DB)
- Patchstack (CVE DB, if token set)
- OSV.dev (CVE DB fallback)
- GitHub Releases (binary update check, opt-out via `WPSECSCAN_NO_UPDATE_CHECK=1`)
- VirusTotal / GreyNoise / HackerOne / Bugcrowd / Intigriti (only if
  used)

**All of these honor `--proxy` too.** With a proxy set, your tracked
sites never see the scanner's real IP — neither do the third-party
intel services. With `WPSECSCAN_NO_NETWORK=1`, the scanner stops
talking to anything except the target (no CVE refresh, no telemetry).
