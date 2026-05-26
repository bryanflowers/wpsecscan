"""Item #63 — Slack slash-command app.

Different from the existing incoming-webhook notify path:
  • incoming webhook = WPSecScan pushing alerts INTO Slack
  • slash command   = a Slack user typing `/wpsecscan URL` INTO Slack and
                       WPSecScan launching a scan in response

This is a tiny stdlib-only HTTP server (no Flask, no FastAPI) that:

  1. Verifies the request signature using Slack's HMAC-SHA256 protocol
     (X-Slack-Signature + X-Slack-Request-Timestamp).
  2. Parses the slash-command form body.
  3. Replies <3 seconds with a 200 + "Scan starting…".
  4. Forks the scan in the background; on completion, POSTs a final
     summary back to Slack via the slash command's `response_url`.

Run with:  wpsecscan slack-app --port 5000 \\
            (set $WPSECSCAN_SLACK_SIGNING_SECRET first)

Put it behind a reverse proxy with TLS. Slack will not accept HTTP.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import httpx


def _verify_slack_signature(secret: str, ts: str, body: bytes, sig: str) -> bool:
    if not (secret and ts and sig):
        return False
    try:
        if abs(time.time() - float(ts)) > 60 * 5:
            return False  # replay-window: 5 minutes
    except ValueError:
        return False
    base = f"v0:{ts}:".encode() + body
    digest = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)


def _run_scan_and_reply(target: str, response_url: str) -> None:
    """Background worker: run a one-shot wpsecscan + POST a Slack message back."""
    try:
        cmd = [sys.executable, "-m", "wpsecscan", target, "--json-only", "--no-console"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        snippet = (proc.stdout or proc.stderr).strip()[-500:]
        text = f"*WPSecScan: {target}*\n```{snippet}```"
    except subprocess.TimeoutExpired:
        text = f"WPSecScan timed out scanning `{target}` after 10 min."
    except Exception as e:  # noqa: BLE001
        text = f"WPSecScan failed: {e}"
    try:
        with httpx.Client(timeout=10.0) as c:
            c.post(response_url, json={"response_type": "in_channel", "text": text})
    except httpx.RequestError:
        pass


class _Handler(BaseHTTPRequestHandler):
    server_version = "WPSecScan-Slack/1.0"

    def log_message(self, fmt, *args):  # noqa: A003 — quiet stdlib logger
        pass

    def do_POST(self):  # noqa: N802 — stdlib API name
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        secret = os.environ.get("WPSECSCAN_SLACK_SIGNING_SECRET", "")
        ts = self.headers.get("X-Slack-Request-Timestamp", "")
        sig = self.headers.get("X-Slack-Signature", "")
        if not _verify_slack_signature(secret, ts, body, sig):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"signature check failed")
            return
        form = parse_qs(body.decode("utf-8", errors="replace"))
        text = (form.get("text", [""])[0]).strip()
        response_url = form.get("response_url", [""])[0]
        if not text:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"text": "usage: /wpsecscan https://example.com"}).encode())
            return
        target = text.split()[0]
        if "://" not in target:
            target = "https://" + target
        # Reply immediately so Slack doesn't time us out at 3s.
        ack = {"response_type": "in_channel",
                "text": f"WPSecScan scanning `{target}`… results in a moment."}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(ack).encode())
        # Kick the actual scan off in a background thread.
        threading.Thread(target=_run_scan_and_reply,
                          args=(target, response_url), daemon=True).start()


def serve(host: str = "0.0.0.0", port: int = 5000) -> None:
    if not os.environ.get("WPSECSCAN_SLACK_SIGNING_SECRET"):
        print("ERROR: set $WPSECSCAN_SLACK_SIGNING_SECRET before starting "
               "(get it from your Slack app's Basic Information page).",
               file=sys.stderr)
        sys.exit(2)
    httpd = HTTPServer((host, port), _Handler)
    print(f"WPSecScan Slack slash-command listener on http://{host}:{port}/")
    print("  Configure your Slack app's slash-command Request URL to point here "
           "(over HTTPS via a reverse proxy).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
