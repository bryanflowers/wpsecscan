# Writing your own checks

WPSecScan loads user-supplied Python checks from `~/.wpsecscan/plugins/`
at startup. Each `.py` file there gets sandboxed-imported; one broken
plugin can't take down the others.

## Minimum viable check

`~/.wpsecscan/plugins/wp_debug_log.py`:

```python
from wpsecscan.models import Finding

CHECK_ID = "wp_debug_log"
CHECK_NAME = "wp-content/debug.log accessibility"
IS_AGGRESSIVE = False

async def check(client, ctx):
    r = await client.get("/wp-content/debug.log")
    if r and r.status_code == 200 and r.text:
        return [Finding(
            severity="high",
            title="debug.log served as text",
            evidence=f"{len(r.text)} bytes leaked",
            remediation="Delete debug.log + set WP_DEBUG_LOG=false.",
            url=ctx["target"] + "/wp-content/debug.log",
        )]
    return []
```

That's it. Re-run any scan; your check appears in the list.

## API

Required module attrs:
- `CHECK_ID: str` — unique per plugin
- `CHECK_NAME: str` — display name
- `IS_AGGRESSIVE: bool` — default `False`
- `async def check(client, ctx) -> list[Finding]`

The `client` is a `wpsecscan.http.Client` — has `.get(path)`, `.head(path)`,
`.post(path, ...)`, `.request(method, path, ...)`. Returns a response
object or `None` on failure.

The `ctx` dict carries `target`, `shared` (cross-check data — e.g.
`shared["waf"]` from the `waf` check), and `step` (a callable for live
dashboard updates: `ctx["step"]("probing X...")`).

## `Finding` fields

| Field | Type | Required |
|-------|------|----------|
| `severity` | str — one of `info`, `low`, `medium`, `high`, `critical` | yes |
| `title` | str — short headline | yes |
| `evidence` | str — what proved it | no |
| `remediation` | str — how to fix | no |
| `url` | str — where the problem lives | no |
| `extra` | dict — arbitrary metadata | no |

## Tags + compliance for your check

Drop a JSON overlay into `~/.wpsecscan/check_tags.json` (overrides the
built-in for matching `CHECK_ID`):

```json
{
  "wp_debug_log": {
    "owasp": "A05:2021",
    "owasp_label": "Security Misconfiguration",
    "attack": "T1592.002",
    "attack_label": "Software",
    "cwe": "CWE-200",
    "d3fend": "D3-RAC"
  }
}
```

Same overlay pattern works for `compliance_map.json`, `compliance_extra.json`,
`compliance_v2.json`.

## Guard rails to follow

The bundled checks all enforce these — yours should too:

- Add `step = ctx.get("step") or (lambda _s: None)` and call it before
  each network round-trip so the live dashboard updates
- Timeout every external call (`client.get()` already has one)
- Don't write files outside `~/.wpsecscan/` without a symlink guard
- If you call an LLM, short-circuit on `os.environ.get("WPSECSCAN_NO_AI")`
- Never log secrets — use `wpsecscan.ai_safety.mask_private()` on
  any user-content that hits a log

## Submitting upstream

If your check is general-purpose, open a PR! See [CONTRIBUTING.md](https://github.com/bryanflowers/wpsecscan/blob/main/CONTRIBUTING.md).
