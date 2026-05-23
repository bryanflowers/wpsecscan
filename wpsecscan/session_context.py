"""#20 + #25 (from ZAP) — saved authentication contexts + session re-auth.

A "context" is a JSON file at ~/.wpsecscan/contexts/<name>.json describing
how to log into a target:

    {
      "name": "production",
      "target": "https://example.com",
      "login_url": "/wp-login.php",
      "login_form": {"log": "admin", "pwd": "$ENV:WPSEC_PROD_PASS"},
      "success_regex": "wp-admin",
      "failure_regex": "ERROR.*incorrect|invalid",
      "csrf_field": "_wpnonce",
      "session_cookies": ["wordpress_logged_in_*"]
    }

`$ENV:NAME` placeholders pull from environment so the file itself never
contains a real password. The scanner uses the context to:
  1. log in once at scan start
  2. detect mid-scan session timeout via failure_regex
  3. re-authenticate automatically and replay the failed request

This module just handles the storage + login flow. Integration with the
scan loop is wired into __main__.py via `--context <name>`.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


def contexts_dir() -> Path:
    from . import history as _h
    return Path(_h._home()) / "contexts"


def list_contexts() -> list[str]:
    d = contexts_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


def load(name: str) -> dict | None:
    p = contexts_dir() / f"{name}.json"
    if not p.exists():
        return None
    try:
        ctx = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # Substitute $ENV:NAME placeholders
    def _sub(v):
        if isinstance(v, str) and v.startswith("$ENV:"):
            return os.environ.get(v[5:], "")
        return v
    if isinstance(ctx.get("login_form"), dict):
        ctx["login_form"] = {k: _sub(v) for k, v in ctx["login_form"].items()}
    return ctx


def save(name: str, data: dict) -> None:
    d = contexts_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.json"
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


async def login(client, context: dict) -> bool:
    """Run the login flow. Returns True if `success_regex` matched in the response."""
    login_url = context.get("login_url", "/wp-login.php")
    form = dict(context.get("login_form") or {})
    csrf_field = context.get("csrf_field")
    # Fetch the login page first to extract any CSRF nonce
    if csrf_field:
        r = await client.get(login_url)
        if r is not None:
            m = re.search(rf'name=["\']{re.escape(csrf_field)}["\']\s+value=["\']([^"\']+)', r.text or "")
            if m:
                form[csrf_field] = m.group(1)
    # POST the credentials
    r = await client.request("POST", login_url, data=form,
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r is None:
        return False
    success_re = context.get("success_regex") or "wp-admin"
    return re.search(success_re, r.text or "") is not None


async def is_logged_out(response, context: dict) -> bool:
    """Heuristic: did the response indicate the session was lost?"""
    failure_re = context.get("failure_regex")
    if not failure_re or response is None:
        return False
    return re.search(failure_re, response.text or "") is not None
