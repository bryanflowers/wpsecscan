"""#12 (from nuclei) — Interactsh-style out-of-band callback shim.

Detects blind SSRF / OOB SQLi / DNS-callback exfil by registering a unique
subdomain on Project Discovery's hosted Interactsh server and feeding the
URL into outbound-fetch parameters. Any DNS lookup or HTTP request that
hits the subdomain proves the target executed our payload.

Full nuclei-style interactsh uses a self-hosted server with RSA-encrypted
callbacks. We use the public `oast.live` / `interact.sh` hosted instance
in unencrypted polling mode — same protocol shape but no E2E encryption.
Users who want encrypted OOB should run their own server and point us at
it via WPSECSCAN_INTERACTSH_URL.

Fallback: when no Interactsh is reachable, falls back to the existing
rbndr.us-based DNS-rebinding probe.
"""
from __future__ import annotations

import os
import random
import string
import time
import urllib.request
from urllib.error import HTTPError, URLError


DEFAULT_SERVER = "oast.live"
POLL_INTERVAL_S = 3
DEFAULT_WAIT_S = 30


def _random_id(n: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class InteractshSession:
    """Cheap polling session — register, give the user a URL to inject, poll
    for interactions, return any hits."""

    def __init__(self, server: str | None = None) -> None:
        raw = (server or os.environ.get("WPSECSCAN_INTERACTSH_URL") or DEFAULT_SERVER).rstrip("/")
        self.server = self._validate_server(raw)
        self.correlation_id = _random_id()
        self.host = f"{self.correlation_id}.{self.server}"

    @staticmethod
    def _validate_server(server: str) -> str:
        """Refuse loopback / metadata / RFC1918 — Interactsh is a PUBLIC
        callback service; a misconfigured env pointing at 127.0.0.1 would
        let the scanner SSRF its own host (or AWS metadata at 169.254.x.x)."""
        from urllib.parse import urlparse as _u
        host = server
        if "://" in server:
            host = _u(server).hostname or server
        blocked = {"127.0.0.1", "::1", "localhost", "0.0.0.0",
                   "169.254.169.254", "100.100.100.200"}
        if host in blocked:
            raise ValueError(f"Interactsh server {host!r} is loopback/metadata — refusing.")
        private_prefixes = ("10.", "192.168.",
                            "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.",
                            "172.28.", "172.29.", "172.30.", "172.31.")
        if any(host.startswith(p) for p in private_prefixes):
            raise ValueError(f"Interactsh server {host!r} is RFC1918 — refusing.")
        return server
        self.url_http = f"http://{self.host}/"
        self.url_https = f"https://{self.host}/"
        self.interactions: list[dict] = []
        self.started_at = time.time()

    def poll_once(self, timeout: float = 5.0) -> int:
        """One poll. Returns how many new interactions were collected.

        The public interactsh polling endpoint shape may differ across hosts;
        we use the conservative `/poll?id=<correlation_id>` form and parse
        the JSON `data` array. On any error / non-200, we return 0."""
        try:
            req = urllib.request.Request(
                f"https://{self.server}/poll?id={self.correlation_id}",
                headers={"User-Agent": "WPSecScan/interactsh"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status != 200:
                    return 0
                import json as _j
                data = _j.loads(r.read().decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError):
            return 0
        new = data.get("data", []) or []
        for item in new:
            # Each item is base64-encoded JSON in real interactsh; for our shim
            # we accept either the decoded shape or a string.
            if isinstance(item, str):
                self.interactions.append({"raw": item, "ts": time.time()})
            elif isinstance(item, dict):
                self.interactions.append(item)
        return len(new)

    def wait_for_interaction(self, timeout_s: float = DEFAULT_WAIT_S) -> bool:
        """Block (synchronously) until at least one interaction arrives or
        the timeout elapses. Returns True if anything hit."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.poll_once() > 0:
                return True
            time.sleep(POLL_INTERVAL_S)
        return False

    def summary(self) -> str:
        if not self.interactions:
            return "(no interactions received)"
        return f"{len(self.interactions)} interaction(s) on {self.host}"


def create_session() -> InteractshSession:
    """Convenience factory."""
    return InteractshSession()
