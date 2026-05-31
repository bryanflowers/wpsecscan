# SDK helpers

Some `wpsecscan` modules are designed to be called programmatically from
Python rather than via the CLI. This page lists them.

## Why SDK-only?

A helper stays SDK-only when its inputs (callable LLM functions,
in-memory image buffers, multi-tier configurations) don't fit a
one-shot CLI invocation.

## `wpsecscan.ai_v28`

CLI surface (via `wpsecscan ai <SUB>`):
- `agentic_remediation_loop(finding, llm_fn=...)`
- `self_improving_scan_plan(target)`
- `visual_diff_summarise(old, new, llm_fn=...)`
- `detect_prompt_injection_in_response(text)`
- `anomaly_drift_alert(target, current_score)`
- `auto_control_mapper(report, framework="hipaa")`

SDK-only:
- **`screenshot_vision_analyse(png_path, llm_fn=...)`** — pass a
  multimodal `llm_fn(prompt, image_path) -> str` callable for
  admin-panel screenshot analysis. Requires a vision-capable model.
- **`sandboxed_exec(cmd, timeout_s=30)`** — run a command inside
  bwrap (Linux) for isolation. macOS + Windows return skipped.
- **`cached_llm(prompt, template_version=..., llm_fn=...)`** —
  disk-backed prompt/response cache keyed on
  `(template_version, sha256(prompt))`. TTL configurable.
- **`model_with_budget_fallback(prompt, budget_cents=..., tier_fns=[(cost, fn), ...])`** —
  cheap-tier-first LLM fallback under a cents budget. Define your
  tier ladder per-call.

## `wpsecscan.compliance_v28`

Most helpers are exposed via `wpsecscan emit`. The exceptions:

- **`whitelabel_pdf_theme(brand_name, logo_path, accent_color)`** —
  returns a theme dict consumable by `reporters.auditor_pdf`. Pass it
  to your reporter call site as the `theme=` kwarg.
- **`tenant_isolated_home(tenant_id)`** — returns a Path object for
  per-tenant `~/.wpsecscan/tenants/<id>/`. Set `WPSECSCAN_HOME` to
  this path before invoking scans for that tenant.
- **`scim_user_to_creds(scim_user)`** — translate a SCIM 2.0 User
  object dict into a wpsecscan creds-vault entry. Used by enterprise
  SSO/SCIM integrations.

## `wpsecscan.integrations_v28`

All 13 functions are exposed via `wpsecscan push`. SDK-only access
is preserved for programmatic call sites — import and call directly:

```python
from wpsecscan import integrations_v28 as iv
from wpsecscan.scanner import scan
import asyncio

report = asyncio.run(scan("https://example.com"))
ok, msg = iv.circleci_orb_emit(report)
```

The shared helpers `_post_json` and `_sanitize_for_subprocess` are
prefixed underscore but stable; rely on them at your own risk.

## `wpsecscan.json_migrations`

Programmatic helper for upgrading unversioned state JSON files.

```python
from wpsecscan import json_migrations as jm

data = jm.load_versioned(
    "~/.wpsecscan/replay-prompt-log.json",
    kind="replay_prompt_log",
    current_version=1,
    inplace=True,
    backup=True,  # writes <path>.bak first
)
```

## `wpsecscan.cli_error`

```python
from wpsecscan.cli_error import CliError, handle_cli_error
import sys

try:
    do_work()
except CliError as e:
    sys.exit(handle_cli_error(e))  # plain mode
    # OR sys.exit(handle_cli_error(e, json_mode=True))  # CI mode
```
