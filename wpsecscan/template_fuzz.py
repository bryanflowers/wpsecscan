"""#16 (from nuclei) — fuzz mode for templates.

When a template includes `payloads:` and a `fuzz:` flag, we run every
combination of payload-value × url-parameter and check matchers for each.

Example template:

    id: sqli-fuzz
    info: { name: SQLi fuzz, severity: high }
    http:
      - method: GET
        path: ["{{BaseURL}}/?id={{payload}}"]
        fuzz: true
        payloads:
          payload:
            - "1 OR 1=1"
            - "1' OR '1'='1"
            - "1 UNION SELECT NULL--"
        matchers:
          - type: regex
            regex: ["SQL syntax|MySQL server|ORA-[0-9]+"]
"""
from __future__ import annotations

from .http import Client
from .models import Finding


async def run_fuzz_template(template: dict, client: Client, ctx: dict) -> list[Finding]:
    from . import template_engine as _te

    info = template.get("info") or {}
    sev = ({"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info"}
           .get((info.get("severity") or "info").lower(), "info"))
    name = info.get("name") or template.get("id", "unnamed")

    findings: list[Finding] = []
    for http_block in (template.get("http") or []):
        if not http_block.get("fuzz"):
            continue
        method = (http_block.get("method") or "GET").upper()
        paths = http_block.get("path") or []
        if isinstance(paths, str):
            paths = [paths]
        payloads_map = http_block.get("payloads") or {}
        if not payloads_map:
            continue
        # Use the first payload key only — keep this simple
        key, values = next(iter(payloads_map.items()))
        for path_template in paths:
            for value in values:
                path = (str(path_template)
                        .replace("{{BaseURL}}", "")
                        .replace("{{" + key + "}}", str(value)))
                if not path.startswith("/") and not path.startswith("http"):
                    path = "/" + path
                try:
                    r = await client.request(method, path)
                except Exception:  # noqa: BLE001
                    continue
                if r is None:
                    continue
                matched, _ = _te._evaluate_request(http_block, r)
                if matched:
                    findings.append(Finding(
                        severity=sev,
                        title=f"[fuzz template] {name} — payload: {str(value)[:40]!r}",
                        evidence=f"{method} {path} matched template '{template.get('id', '?')}' fuzz block.",
                        remediation=info.get("description") or "See template for context.",
                        url=client.url(path),
                        extra={"template_id": template.get("id"), "payload": value},
                    ))
                    break  # one finding per template is enough
            else:
                continue
            break
    return findings
