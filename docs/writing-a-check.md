# Writing a WPSecScan check

Round-64 #151 — full tutorial.

## The shape of a check

A check is a single Python module under `wpsecscan/checks/`. It must
expose one function:

```python
async def check(client: Client, ctx: dict) -> list[Finding]:
    ...
```

## Minimum viable check

```python
"""Probe /readme.html — the WordPress version-leak file."""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("checking /readme.html...")
    r = await client.get("/readme.html")
    if r is not None and r.status_code == 200 and "WordPress" in (r.text or ""):
        findings.append(Finding(
            severity="low",
            title="WordPress readme.html is publicly accessible",
            evidence=f"GET /readme.html -> 200 ({len(r.text or '')} bytes)",
            remediation="Block /readme.html in your web-server config; it leaks the WP version.",
            url=client.url("/readme.html"),
        ))
    return findings
```

## Steps

1. **Use the scaffolder**:
   ```bash
   python scripts/new-check.py --id my_check
   ```

2. **Implement** the logic. Always:
   - Use `client.get(path)` / `client.post(path, ...)` — never `requests`/`httpx` directly
   - Return `Finding` instances (severity, title, evidence, remediation, url)
   - Call `step("describing what you're doing")` so GUI users see progress
   - Handle `None` responses (network failure → `r is None`)
   - Catch only specific exceptions, never bare `except:`

3. **Register** in `wpsecscan/checks/__init__.py`:
   ```python
   from .my_check import check as my_check
   ALL_CHECKS.append(("my_check", "My check", my_check, False))
   ```

4. **Tag**: add an entry to `wpsecscan/data/check_tags.json`:
   ```json
   "my_check": {
     "owasp": ["A05:2021"],
     "mitre_attack": ["T1190"],
     "cwe": ["CWE-200"]
   }
   ```

5. **Test** in `tests/test_my_check.py`:
   ```python
   from tests.check_framework import FakeClient, FakeResponse, _ctx, run
   from wpsecscan.checks.my_check import check as my_check

   def test_finds_readme():
       c = FakeClient({("GET", "/readme.html"): FakeResponse(200, "WordPress 6.5")})
       findings = run(my_check(c, _ctx()))
       assert any("readme" in f.title.lower() for f in findings)
   ```

6. **Lint**:
   ```bash
   python scripts/lint-checks.py
   ```

## Severities

| Severity | When to use |
|----------|-------------|
| critical | Active exploit / immediate compromise risk |
| high     | Exploitable in <1 hop; admin compromise likely |
| medium   | Real but not exploitable on its own |
| low      | Best practice violation; hardening |
| info     | Observation; no action |

## ctx — what's in it

| Key | Type | Description |
|-----|------|-------------|
| step | callable | Progress hook (GUI / TTY) |
| shared | dict | Mutable state shared across checks (e.g. detected WP version) |
| aggressive | bool | True when --aggressive mode |
| authenticated | bool | True when admin cookie is present |
| compliance | dict | Compliance-mapping settings for this scan |

## Performance tips

- Cache via the `Client`'s built-in cache (free)
- Multiple parallel requests: use `asyncio.gather`
- Avoid `time.sleep` — use `await asyncio.sleep`
- Don't fingerprint files that other checks already detected;
  read from `ctx["shared"]` instead

## Aggressive (active) checks

If your check sends a payload that:
- Mutates server state
- Is detectable as an attack by a WAF
- Could plausibly trigger an IDS

set `aggressive=True` in the `ALL_CHECKS` tuple. These only run when
the user passes `--aggressive`.

## Companion-plugin checks

If your check needs data only the companion WP plugin can provide
(e.g. DB triggers, MFA status), query:
`/wp-json/wpsecscan-companion/v1/<endpoint>` and handle 404 gracefully
(plugin not installed).

## Don't

- Don't trigger destructive operations (deletes, account creates) —
  even with `--aggressive`
- Don't write to the target filesystem
- Don't include the user's API keys in finding `evidence`
- Don't `print()` — use `step()` or the logger
- Don't read environment variables for behaviour switches not in `ctx`
