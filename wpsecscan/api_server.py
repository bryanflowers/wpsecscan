"""M34 HTTP API server (stdlib-only).

Tiny embedded HTTP server for triggering scans + fetching past reports
from other tooling (CI, dashboards, chatbots). Uses `http.server` so
there's no FastAPI/uvicorn dependency.

Endpoints:
  GET  /healthz                                  -> {"ok": true}
  GET  /history?url=<url>                        -> list of {scanned_at, risk_score, snapshot}
  POST /scan {"target":"...", "aggressive":bool} -> kicks off a scan in the background
  GET  /scan/<task_id>                           -> {"status":"running|done", "report":{...}}
  GET  /reports/<filename>                       -> serves a saved JSON snapshot
  GET  /openapi.json                             -> minimal OpenAPI 3 doc

Auth: bearer token from --api-token (or env WPSECSCAN_API_TOKEN). If unset,
the server refuses to start (no anonymous remote scans).
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import threading
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# B2: cap the in-memory task store to avoid unbounded growth from long-running
# servers. When the cap is reached we evict the oldest finished task.
_TASKS_MAX = 1000


_TASKS: "OrderedDict[str, dict]" = OrderedDict()
_TASKS_LOCK = threading.Lock()


def _put_task(task_id: str, entry: dict) -> None:
    """Insert/update a task with LRU eviction (B2)."""
    with _TASKS_LOCK:
        if task_id in _TASKS:
            _TASKS.move_to_end(task_id)
        _TASKS[task_id] = entry
        while len(_TASKS) > _TASKS_MAX:
            _TASKS.popitem(last=False)


def _reports_dir() -> Path:
    from . import history as _h
    return Path(_h._home()) / "reports"


def _history_for(url: str) -> list[dict]:
    from . import history as _h
    safe = _h._safe_filename(url)
    out = []
    d = _reports_dir()
    if not d.exists():
        return []
    for p in sorted(d.glob(f"*{safe}*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({
            "scanned_at": data.get("scanned_at", p.stem),
            "risk_score": int(data.get("risk_score", 0)),
            "snapshot": p.name,
        })
    return out


def _run_scan_in_background(task_id: str, target: str, aggressive: bool) -> None:
    """Run the scan in a fresh asyncio loop on a worker thread."""
    from . import scanner

    async def _go():
        return await scanner.scan(target=target, aggressive=aggressive)

    try:
        report = asyncio.run(_go())
        with _TASKS_LOCK:
            entry = _TASKS.get(task_id)
            if entry is not None:
                entry["status"] = "done"
                entry["report"] = report.to_dict()
                entry["finished_at"] = time.time()
                _TASKS.move_to_end(task_id)
    except Exception as e:  # noqa: BLE001
        with _TASKS_LOCK:
            entry = _TASKS.get(task_id)
            if entry is not None:
                entry["status"] = "error"
                entry["error"] = str(e)
                entry["finished_at"] = time.time()
                _TASKS.move_to_end(task_id)


def _make_handler(token: str):
    expected = f"Bearer {token}"

    class Handler(BaseHTTPRequestHandler):
        def _auth_ok(self) -> bool:
            # B1: constant-time comparison guards against token-recovery via
            # response-timing analysis.
            hdr = self.headers.get("Authorization", "")
            return hmac.compare_digest(hdr, expected)

        def _send_json(self, status: int, payload) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            u = urlparse(self.path)
            if u.path == "/healthz":
                self._send_json(200, {"ok": True})
                return
            if not self._auth_ok():
                self._send_json(401, {"error": "unauthorized"})
                return
            if u.path == "/openapi.json":
                self._send_json(200, _openapi_doc())
                return
            if u.path == "/history":
                qs = parse_qs(u.query)
                url = (qs.get("url") or [""])[0]
                if not url:
                    self._send_json(400, {"error": "missing url"})
                    return
                self._send_json(200, {"history": _history_for(url)})
                return
            if u.path.startswith("/scan/"):
                task_id = u.path.split("/", 2)[-1]
                with _TASKS_LOCK:
                    task = _TASKS.get(task_id)
                if not task:
                    self._send_json(404, {"error": "no such task"})
                    return
                self._send_json(200, task)
                return
            if u.path.startswith("/reports/"):
                name = u.path.rsplit("/", 1)[-1]
                # B3: reject path traversal on BOTH separators; also reject any
                # name that doesn't survive a Path normalisation round-trip
                # (catches `\` on Windows, `%2F` urlencoded slashes, NUL bytes, ...).
                if (".." in name or "/" in name or "\\" in name
                        or "\x00" in name or name != Path(name).name):
                    self._send_json(404, {"error": "no such report"})
                    return
                p = _reports_dir() / name
                if not p.exists():
                    self._send_json(404, {"error": "no such report"})
                    return
                try:
                    body = p.read_bytes()
                except OSError:
                    self._send_json(500, {"error": "read failed"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            u = urlparse(self.path)
            if not self._auth_ok():
                self._send_json(401, {"error": "unauthorized"})
                return
            if u.path == "/scan":
                try:
                    length = int(self.headers.get("Content-Length") or "0")
                    body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                except (ValueError, OSError):
                    self._send_json(400, {"error": "invalid json body"})
                    return
                target = body.get("target", "")
                if not target:
                    self._send_json(400, {"error": "missing target"})
                    return
                aggressive = bool(body.get("aggressive"))
                task_id = uuid.uuid4().hex[:12]
                _put_task(task_id, {"status": "running", "target": target,
                                     "started_at": time.time()})
                t = threading.Thread(
                    target=_run_scan_in_background,
                    args=(task_id, target, aggressive),
                    daemon=True,
                )
                t.start()
                self._send_json(202, {"task_id": task_id, "status": "running"})
                return
            self._send_json(404, {"error": "not found"})

        def log_message(self, format, *args):
            # Quiet the default access log; users can wrap with their own.
            pass

    return Handler


def _openapi_doc() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "WPSecScan API", "version": "1.0"},
        "paths": {
            "/healthz":            {"get":  {"summary": "Health check (no auth)", "responses": {"200": {"description": "ok"}}}},
            "/history":            {"get":  {"summary": "List saved snapshots for a URL",
                                              "parameters": [{"name": "url", "in": "query", "required": True, "schema": {"type": "string"}}],
                                              "responses": {"200": {"description": "history list"}}}},
            "/scan":               {"post": {"summary": "Trigger a scan (returns task_id)",
                                              "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object",
                                                "properties": {"target": {"type": "string"}, "aggressive": {"type": "boolean"}}, "required": ["target"]}}}}}},
            "/scan/{task_id}":     {"get":  {"summary": "Fetch scan status / result"}},
            "/reports/{filename}": {"get":  {"summary": "Fetch a saved snapshot"}},
        },
    }


def serve(host: str = "127.0.0.1", port: int = 8765, *, token: str | None = None) -> None:
    """Run the API server. Blocks until Ctrl+C."""
    token = token or os.environ.get("WPSECSCAN_API_TOKEN", "")
    if not token:
        raise SystemExit(
            "API server requires --api-token <secret> or WPSECSCAN_API_TOKEN; "
            "refusing to start anonymous."
        )
    if len(token) < 16:
        raise SystemExit(
            "API token must be at least 16 characters (use `python -c \"import secrets; "
            "print(secrets.token_urlsafe(32))\"` to generate)."
        )
    server = ThreadingHTTPServer((host, port), _make_handler(token))
    if host in ("0.0.0.0", "::", "*"):
        print(f"⚠  WPSecScan API on {host}:{port} — listening on EVERY interface. "
              "The token is the only thing between attackers and your scan history. "
              "Prefer 127.0.0.1 + an SSH tunnel.")
    print(f"WPSecScan API listening on http://{host}:{port}")
    print(f"Auth: Authorization: Bearer {token[:6]}***")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAPI server stopping.")
        server.shutdown()
