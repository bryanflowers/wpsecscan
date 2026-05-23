"""#29 (from ZAP) — JS scriptable check loader.

Users who'd rather write a check in JavaScript can drop a `.js` file
into ~/.wpsecscan/plugins/. The JS file must export `check(input)` that
takes a JSON object {target, body, headers, status} and returns a JSON
array of finding objects.

Execution: we shell out to `node` (Node.js required on PATH). Each JS
plugin runs in a fresh Node child-process with the input piped on stdin
and the result captured from stdout. No npm packages — plain JS only.

Example ~/.wpsecscan/plugins/my_check.js:

    function check(input) {
      const findings = [];
      if (input.body && input.body.includes("MY_MARKER")) {
        findings.push({
          severity: "medium",
          title: "Custom JS finding",
          evidence: "Body contained MY_MARKER",
          remediation: "Remove MY_MARKER from public output.",
          url: input.target
        });
      }
      return findings;
    }
    process.stdin.on("data", b => {
      const out = check(JSON.parse(b.toString()));
      process.stdout.write(JSON.stringify(out));
    });

Falls back silently when Node isn't installed.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path


def _plugins_dir() -> Path:
    from . import history as _h
    return Path(_h._home()) / "plugins"


def list_js_plugins() -> list[Path]:
    d = _plugins_dir()
    if not d.exists():
        return []
    return sorted(d.glob("*.js"))


def has_node() -> bool:
    return shutil.which("node") is not None


MAX_STDOUT_BYTES = 10 * 1024 * 1024  # 10 MB cap — anything bigger is a runaway script


async def run_js_plugin(plugin_path: Path, input_obj: dict, timeout: float = 5.0) -> list[dict]:
    """Run one JS plugin. Returns the parsed list of findings (may be empty).
    Caps stdout at MAX_STDOUT_BYTES so a runaway script can't OOM the scanner."""
    if not has_node():
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "node", str(plugin_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=MAX_STDOUT_BYTES,
        )
        stdout_bytes = bytearray()
        try:
            proc.stdin.write(json.dumps(input_obj).encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()
            while len(stdout_bytes) < MAX_STDOUT_BYTES:
                chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=timeout)
                if not chunk:
                    break
                stdout_bytes.extend(chunk)
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            return []
    except (FileNotFoundError, OSError):
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(bytes(stdout_bytes).decode("utf-8") or "[]")
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [f for f in data if isinstance(f, dict)]
