# Troubleshooting common scan errors

Mirrors the GUI's `_suggest_for_error()` guidance for CLI users.

## TLS verification failed

**Symptom**: `ssl.SSLCertVerificationError: certificate verify failed`.

**Fixes**:
- The target's certificate is invalid or expired. Verify with
  `openssl s_client -connect host:443`.
- For known self-signed test sites only: `wpsecscan <url> --insecure`.
  Do not use `--insecure` against production targets.

## DNS lookup failed

**Symptom**: `socket.gaierror: [Errno 11001] getaddrinfo failed`.

**Fixes**:
- Confirm the host is reachable from your machine: `nslookup <host>`.
- Behind a corporate proxy? Set `HTTP_PROXY` / `HTTPS_PROXY` env vars
  OR pass `--proxy http://your.proxy:8080`.
- Try a different DNS resolver: `WPSECSCAN_DNS_SERVER=1.1.1.1`.

## HTTP 403 Forbidden on every probe

**Symptom**: WAF detected; finding evidence shows blocked responses.

**Fixes**:
- Allow-list your scanner IP in the WAF (Cloudflare / Wordfence /
  Sucuri / WP Cerber). Authorized scanning requires it.
- For Cloudflare, set `--user-agent "Mozilla/5.0 (compatible; ...)"`
  to a less obvious one. Note: WPSecScan refuses to spoof browsers
  by default; you must opt in explicitly.

## HTTP 429 Too Many Requests

**Symptom**: rate-limit exhaustion; most checks return empty.

**Fixes**:
- Lower concurrency: `--concurrency 2`.
- Enable polite pacing: `--timeout 30` (more relaxed).
- If the site has its own rate-limit (rate-limit-by-IP), your scan
  shares the bucket with legitimate users. Schedule scans for
  off-peak windows.

## Connection refused / connection reset

**Symptom**: TCP-level failure mid-scan.

**Fixes**:
- Target may be temporarily down. Verify with `curl -I <url>`.
- Aggressive checks can trip an IDS/IPS into dropping traffic. Run
  passive-only first: `wpsecscan <url>` (no `--aggressive`).
- A Cloudflare "I'm under attack" mode will reset connections —
  pause it for the duration of the scan window.

## Read timeout

**Symptom**: `httpx.ReadTimeout` errors.

**Fixes**:
- Increase `--timeout 60` (default is 30s).
- The target is slow under load. Combine with `--concurrency 1` to
  serialize requests so the server has time to respond.

## Proxy auth failed

**Symptom**: `httpx.ProxyError: 407 Proxy Authentication Required`.

**Fixes**:
- Pass `--proxy-auth user:pass` alongside `--proxy <url>`.
- For NTLM proxies, see `docs/proxy.md` for the `httpx-ntlm` setup.

## v2.8.1 CI progress dots not appearing

**Symptom**: piped output is silent during scan.

**Fix**: this was a regression in v2.8.1 (`_ci_on_progress` parameter
order was reversed). Upgrade to v2.8.2.

## `--out` raising `argparse.ArgumentError`

**Symptom**: any v2.8.1 invocation using `--out` raises
"ambiguous option: --out".

**Fix**: this was a regression introduced by the `--output` alias in
v2.8.1. Upgrade to v2.8.2.

## Open an issue

For anything not covered: <https://github.com/bryanflowers/wpsecscan/issues>
