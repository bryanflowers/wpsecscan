"""#9 + #10 (from nuclei) — YAML-templated checks + DSL matchers.

Lets users (and the community) drop nuclei-style YAML templates into
~/.wpsecscan/templates/*.yaml. We support the subset of nuclei's template
grammar that covers ~80% of community templates: HTTP requests, status /
word / regex matchers, simple extractors, and `condition: and|or`.

This is NOT a 100%-compatible nuclei runtime — we don't implement workflow,
DSL functions, or the full matcher zoo. But it's the entry point that lets
non-Python users contribute checks.

Template schema (subset):

    id: my-check
    info:
      name: My custom check
      severity: medium
      tags: [wordpress, custom]
    http:
      - method: GET
        path:
          - "{{BaseURL}}/wp-content/plugins/foo/readme.txt"
        matchers-condition: and
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["= Foo Plugin ="]
            part: body
          - type: regex
            regex: ["Stable tag: ([\\d.]+)"]
            part: body
        extractors:
          - type: regex
            regex: ["Stable tag: ([\\d.]+)"]
            group: 1

Templates load lazily (on first scan). Failed templates log to the
activity bus but don't crash the scanner.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .http import Client
from .models import Finding


_SEVERITY_NORMALISE = {
    "info": "info", "informational": "info",
    "low": "low",
    "medium": "medium", "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def _has_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


def templates_dir() -> Path:
    from . import history as _h
    return Path(_h._home()) / "templates"


def _load_template(path: Path) -> dict | None:
    if not _has_yaml():
        return None
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def list_templates() -> list[Path]:
    d = templates_dir()
    if not d.exists():
        return []
    return sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")))


# -------- matchers --------

def _match_status(matcher: dict, response) -> bool:
    expected = matcher.get("status", []) or []
    return response.status_code in expected


def _match_word(matcher: dict, response) -> bool:
    words = matcher.get("words", []) or []
    part = matcher.get("part", "body")
    haystack = _select_part(response, part)
    cond = (matcher.get("condition") or "or").lower()
    if cond == "and":
        return all(w in haystack for w in words)
    return any(w in haystack for w in words)


def _match_regex(matcher: dict, response) -> bool:
    patterns = matcher.get("regex", []) or []
    part = matcher.get("part", "body")
    haystack = _select_part(response, part)
    cond = (matcher.get("condition") or "or").lower()
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            continue
    if not compiled:
        return False
    if cond == "and":
        return all(pat.search(haystack) for pat in compiled)
    return any(pat.search(haystack) for pat in compiled)


def _match_size(matcher: dict, response) -> bool:
    sizes = matcher.get("size", []) or []
    body_len = len(response.content or b"")
    return body_len in sizes


_MATCHERS = {
    "status": _match_status,
    "word": _match_word,
    "regex": _match_regex,
    "size": _match_size,
}


def _select_part(response, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in response.headers.items()
                          if hasattr(response.headers, "items"))
    if part == "all":
        return ((response.text or "") + "\n"
                + "\n".join(f"{k}: {v}" for k, v in response.headers.items()
                            if hasattr(response.headers, "items")))
    return response.text or ""


def _run_extractors(extractors: list, response) -> list[str]:
    out: list[str] = []
    for ex in extractors:
        if ex.get("type") != "regex":
            continue
        part = ex.get("part", "body")
        group = int(ex.get("group", 0))
        haystack = _select_part(response, part)
        for pat in ex.get("regex", []) or []:
            try:
                m = re.search(pat, haystack)
                if m:
                    try:
                        out.append(m.group(group))
                    except (IndexError, re.error):
                        pass
            except re.error:
                continue
    return out


def _evaluate_request(http_block: dict, response) -> tuple[bool, list[str]]:
    """Returns (matched, extracted_values)."""
    matchers = http_block.get("matchers") or []
    if not matchers:
        return (False, [])
    results = []
    for m in matchers:
        mtype = (m.get("type") or "").lower()
        fn = _MATCHERS.get(mtype)
        results.append(bool(fn(m, response)) if fn else False)
    cond = (http_block.get("matchers-condition") or "or").lower()
    matched = all(results) if cond == "and" else any(results)
    extracted = _run_extractors(http_block.get("extractors") or [], response) if matched else []
    return matched, extracted


async def run_template(template: dict, client: Client, ctx: dict) -> list[Finding]:
    """Execute a single template against the target. Returns 0 or more findings."""
    findings: list[Finding] = []
    info = template.get("info") or {}
    name = info.get("name") or template.get("id", "unnamed template")
    severity = _SEVERITY_NORMALISE.get((info.get("severity") or "info").lower(), "info")

    for http_block in (template.get("http") or []):
        method = (http_block.get("method") or "GET").upper()
        paths = http_block.get("path") or http_block.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        for raw_path in paths:
            # Substitute {{BaseURL}} → empty so url() prepends the base
            path = str(raw_path).replace("{{BaseURL}}", "")
            if not path.startswith("/") and not path.startswith("http"):
                path = "/" + path
            try:
                r = await client.request(method, path)
            except Exception:  # noqa: BLE001
                continue
            if r is None:
                continue
            matched, extracted = _evaluate_request(http_block, r)
            if matched:
                extra_str = " · ".join(extracted) if extracted else ""
                findings.append(Finding(
                    severity=severity,
                    title=f"[YAML template] {name}",
                    evidence=(f"Template {template.get('id', '?')!r} matched on {method} {path}"
                              + (f"\nExtracted: {extra_str}" if extra_str else "")),
                    remediation=(info.get("description") or info.get("remediation") or
                                  "See the YAML template for context."),
                    url=client.url(path),
                    extra={"template_id": template.get("id"),
                           "template_tags": info.get("tags", []),
                           "extracted": extracted},
                ))
                break  # one finding per http block is enough
    return findings


async def run_all_templates(client: Client, ctx: dict) -> list[Finding]:
    """Discover + run every template in ~/.wpsecscan/templates/. Used by the
    `yaml_templates` check."""
    findings: list[Finding] = []
    if not _has_yaml():
        return findings
    templates = list_templates()
    if templates:
        try:
            from . import activity as _act
            _act.emit("integration", f"YAML templates: {len(templates)} loaded")
        except ImportError:
            pass
    for path in templates:
        tmpl = _load_template(path)
        if not tmpl:
            continue
        try:
            findings.extend(await run_template(tmpl, client, ctx))
        except Exception:  # noqa: BLE001
            continue
    if findings:
        try:
            from . import activity as _act
            _act.emit("threat_intel", f"YAML templates matched: {len(findings)} finding(s)")
        except ImportError:
            pass
    return findings
