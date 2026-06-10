"""Item #80 — mobile companion (REST API + PWA).

The plan called for a native iOS/Android app; scope-down to a
Progressive-Web-App lets us ship a phone-installable dashboard in a few
hundred lines instead of standing up two app-store pipelines. The
operator opens the URL on their phone, taps the browser's "Add to home
screen", and gets a full-screen WPSecScan dashboard. Push notifications
on iOS Safari 16.4+ and modern Android Chrome work the same way native
push works in those engines.

The REST API surface:

  GET  /api/reports               list of every site's most-recent report
  GET  /api/report/{safe_host}    one site's full JSON
  GET  /api/manifest.json         PWA manifest
  GET  /api/sw.js                 service worker (cache-first for assets,
                                  network-first for /api/reports)
  GET  /                          PWA shell (index.html)

Authentication: a single shared `X-WPSecScan-Token` header. Token is
read from $WPSECSCAN_MOBILE_TOKEN at server start. Without it the
server refuses to start (preventing accidental open-to-internet).

Run with:  wpsecscan mobile-api --port 8765
Tunnel to your phone with Tailscale / WireGuard; we do NOT recommend
exposing this to the open internet without a reverse-proxy + TLS even
with the shared-token gate.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _list_recent_reports() -> list[dict[str, Any]]:
    """Surface (target, scanned_at, summary, risk_score) for each site whose
    snapshots live in ~/.wpsecscan/reports/."""
    reports_dir = _home() / "reports"
    if not reports_dir.exists():
        return []
    by_host: dict[str, Path] = {}
    for p in sorted(reports_dir.glob("*.json")):
        # Snapshots are named "<safe-host>-<timestamp>.json"; the canonical
        # short report is "<safe-host>.json". Take the lexicographically
        # last entry per safe-host prefix.
        stem = p.stem
        host = stem.rsplit("-", 1)[0] if "-" in stem and stem.rsplit("-", 1)[1].startswith("20") else stem
        prev = by_host.get(host)
        if prev is None or p.stat().st_mtime > prev.stat().st_mtime:
            by_host[host] = p

    out: list[dict[str, Any]] = []
    for host, path in sorted(by_host.items()):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({
            "safe_host": host,
            "target": data.get("target", host),
            "scanned_at": data.get("scanned_at", ""),
            "risk_score": data.get("risk_score", 0),
            "summary": data.get("summary", {}),
            "snapshot_file": path.name,
        })
    return out


def _read_one_report(safe_host: str) -> dict[str, Any] | None:
    reports_dir = _home() / "reports"
    if not reports_dir.exists():
        return None
    # Try canonical name first, then most-recent snapshot
    canonical = reports_dir / f"{safe_host}.json"
    if canonical.exists():
        try:
            return json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    candidates = sorted(reports_dir.glob(f"{safe_host}-*.json"),
                         key=lambda p: p.stat().st_mtime, reverse=True)
    for p in candidates:
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# Static PWA assets
# ---------------------------------------------------------------------------

_PWA_MANIFEST = {
    "name": "WPSecScan",
    "short_name": "WPSecScan",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0d1117",
    "theme_color": "#1f6feb",
    "icons": [
        {"src": "/api/icon-192.png", "sizes": "192x192", "type": "image/png"},
        {"src": "/api/icon-512.png", "sizes": "512x512", "type": "image/png"},
    ],
}

_INDEX_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>WPSecScan</title>
<link rel="manifest" href="/api/manifest.json">
<meta name="theme-color" content="#1f6feb">
<style>
  body { margin:0; padding:0 12px 96px; font:15px -apple-system,"Segoe UI",sans-serif; background:#0d1117; color:#c9d1d9; }
  header { padding:16px 0 8px; }
  h1 { font-size:18px; margin:0; }
  .meta { color:#8b949e; font-size:11px; margin-top:2px; }
  ul#sites { list-style:none; padding:0; margin:0; }
  li.site { background:#161b22; border:1px solid #30363d; border-radius:8px;
              padding:12px; margin:10px 0; }
  li.site h2 { font-size:14px; margin:0 0 4px; }
  .score { font-size:24px; font-weight:700; float:right; }
  .pills { font-size:11px; margin-top:6px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px;
           background:#30363d; margin-right:4px; }
  .pill.critical { background:#67000d; color:#ffd6d6; }
  .pill.high     { background:#5a1816; color:#ff8a85; }
  .pill.medium   { background:#4a3a10; color:#f0c674; }
  .auth-box { background:#161b22; border:1px solid #30363d; border-radius:8px;
                padding:14px; margin:10px 0; }
  input[type=password] { background:#0d1117; border:1px solid #30363d;
                           color:#c9d1d9; padding:8px; border-radius:6px; width:100%; box-sizing:border-box;}
  button { background:#1f6feb; border:0; color:#fff; padding:10px 16px;
             border-radius:6px; margin-top:8px; font-size:14px; }
</style>
</head><body>
<header><h1>WPSecScan</h1><div class="meta" id="meta">Loading…</div></header>
<div id="root"></div>
<script>
(async () => {
  const root = document.getElementById('root');
  const meta = document.getElementById('meta');

  // v2.8.1 B33 — token storage moved from localStorage to
  // sessionStorage. Pre-fix: localStorage persisted the token across
  // sessions AND was readable by any same-origin JS (XSS on a sibling
  // endpoint = token theft). sessionStorage clears on tab close
  // (mitigates one-tab-leak) AND requires re-entry on each browser
  // restart (acceptable for a PWA that's mostly used on demand).
  let token = sessionStorage.getItem('wpsecscan_token') || '';
  if (!token) {
    root.innerHTML = `<div class="auth-box">
      <p>Enter your <code>$WPSECSCAN_MOBILE_TOKEN</code>:</p>
      <input type="password" id="tk">
      <br><button id="save">Save</button>
      <p style="font-size:11px;opacity:0.7;margin-top:8px">Token is stored in sessionStorage and cleared when you close the tab.</p></div>`;
    document.getElementById('save').onclick = () => {
      sessionStorage.setItem('wpsecscan_token', document.getElementById('tk').value);
      location.reload();
    };
    return;
  }

  try {
    const r = await fetch('/api/reports', {headers: {'X-WPSecScan-Token': token}});
    if (r.status === 401) {
      sessionStorage.removeItem('wpsecscan_token');
      location.reload();
      return;
    }
    const sites = await r.json();
    meta.textContent = sites.length + ' site' + (sites.length === 1 ? '' : 's') + ' tracked';
    root.innerHTML = '<ul id="sites">' + sites.map(s => {
      const sev = s.summary || {};
      return `<li class="site">
        <span class="score">${s.risk_score}</span>
        <h2>${escapeHtml(s.target)}</h2>
        <div class="meta">scanned: ${escapeHtml(s.scanned_at)}</div>
        <div class="pills">
          <span class="pill critical">crit ${sev.critical||0}</span>
          <span class="pill high">high ${sev.high||0}</span>
          <span class="pill medium">med ${sev.medium||0}</span>
        </div>
      </li>`;
    }).join('') + '</ul>';
  } catch (e) {
    root.innerHTML = '<p style="color:#ff8a85">Error: ' + e.message + '</p>';
  }
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/api/sw.js').catch(() => {});
  }
  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }
})();
</script>
</body></html>
"""

_SERVICE_WORKER = """
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/reports') || url.pathname.startsWith('/api/report/')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
  } else {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
  }
});
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "WPSecScan-Mobile/1.0"

    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def _cors_origin(self) -> str:
        """v2.8.4 H7 — CORS origin policy. Default `*` so the PWA works
        through a reverse proxy or LAN tunnel; operators can lock down
        via WPSECSCAN_MOBILE_API_CORS_ORIGIN env var."""
        return os.environ.get("WPSECSCAN_MOBILE_API_CORS_ORIGIN", "*")

    def _send_json(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # v2.8.4 H7 — CORS headers so the PWA can be accessed via a
        # different origin (Tailscale tunnel, reverse proxy, etc.).
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Access-Control-Allow-Headers", "X-WPSecScan-Token, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, body: str, *, ctype: str = "text/html") -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        # v2.8.4 H7 — CORS headers (same rationale as _send_json).
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Access-Control-Allow-Headers", "X-WPSecScan-Token, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(raw)

    def _send_404(self) -> None:
        """v2.8.4 H7 — explicit Content-Length on 404 so HTTP/1.1 clients
        don't hang waiting for the body length."""
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.end_headers()

    def _check_auth(self) -> bool:
        expected = os.environ.get("WPSECSCAN_MOBILE_TOKEN", "")
        if not expected:
            return False
        # S6: hmac.compare_digest is constant-time over token length;
        # `==` short-circuits and leaks the matched prefix length via
        # timing. Critical on a noisy LAN.
        import hmac as _hmac
        return _hmac.compare_digest(
            self.headers.get("X-WPSecScan-Token", ""), expected,
        )

    def do_GET(self):  # noqa: N802 — stdlib API
        url = urlparse(self.path)
        path = url.path
        if path == "/" or path == "/index.html":
            return self._send_text(_INDEX_HTML, ctype="text/html")
        if path == "/api/manifest.json":
            return self._send_json(_PWA_MANIFEST)
        if path == "/api/sw.js":
            return self._send_text(_SERVICE_WORKER, ctype="application/javascript")
        if path == "/api/reports":
            if not self._check_auth():
                self.send_response(401); self.end_headers(); return
            return self._send_json(_list_recent_reports())
        if path.startswith("/api/report/"):
            if not self._check_auth():
                self.send_response(401); self.end_headers(); return
            raw = unquote(path.removeprefix("/api/report/"))
            # Path-traversal guard: only the base filename survives, then we
            # confirm the resolved file is actually inside reports_dir.
            # B34 (v2.8.0) — Windows-specific bypass: an attacker URL-
            # encoded backslash (%5C) decoded to `\`, and
            # `Path("foo\\..\\bar").name` on Windows returns `bar`,
            # passing the `safe != raw` guard. Reject ANY backslash
            # AND any forward slash AND any path-separator-related
            # control char outright, BEFORE the Path round-trip.
            if (not raw or "\\" in raw or "/" in raw or "\x00" in raw
                    or ".." in raw):
                self._send_404(); return
            safe = Path(raw).name
            if not safe or safe.startswith(".") or safe != raw:
                self._send_404(); return
            data = _read_one_report(safe)
            if data is None:
                self._send_404(); return
            return self._send_json(data)
        self._send_404()


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    # B46 (v2.8.0) — default bind switched from 0.0.0.0 (LAN-exposed
    # out of the box) to 127.0.0.1 (loopback-only). Operators who
    # want LAN exposure pass `--host 0.0.0.0` explicitly. The token
    # guard exists but defence-in-depth: don't surface a token-gated
    # surface to the LAN by default.
    if not os.environ.get("WPSECSCAN_MOBILE_TOKEN"):
        print("ERROR: set $WPSECSCAN_MOBILE_TOKEN before starting "
               "(any string of >=24 random chars).", file=sys.stderr)
        sys.exit(2)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"WPSecScan mobile companion on http://{host}:{port}/")
    print(f"  PWA shell:           http://localhost:{port}/")
    print(f"  Report list:         http://localhost:{port}/api/reports")
    print("  Tunnel to your phone via Tailscale or WireGuard; do NOT expose "
           "directly to the open internet without TLS + reverse proxy.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
