"""L30 GraphQL-style filter against a report.

Not actual GraphQL (no parser, no schema). A tiny query DSL that returns
findings matching a filter expression. Example:

    findings(severity in [critical,high], check_id startswith ssrf)

Supported ops: =, !=, in [...], startswith, endswith, contains, ~ (regex).
Joined with AND. Multiple filter clauses inside parens.

Used by `wpsecscan --query 'expr'` post-scan, and by the GUI's
"Filter findings..." search box.
"""
from __future__ import annotations

import re
from typing import Any, Iterable


_TOKEN = re.compile(
    r"\s*("
    r"\(|\)|,|\[|\]|"
    r"!=|=|~|"
    # B7: `\b~\b` never matches because `~` isn't a word character.
    r"\bstartswith\b|\bendswith\b|\bcontains\b|\bin\b|"
    r"[A-Za-z_][A-Za-z0-9_]*|"
    r"'[^']*'|"
    r'"[^"]*"|'
    r"[0-9]+"
    r")"
)


def _tokenize(s: str) -> list[str]:
    toks = []
    i = 0
    while i < len(s):
        m = _TOKEN.match(s, i)
        if not m:
            raise ValueError(f"query parse error at index {i}: {s[i:i+20]!r}")
        toks.append(m.group(1))
        i = m.end()
    return toks


def _unquote(t: str) -> str:
    if (t.startswith("'") and t.endswith("'")) or (t.startswith('"') and t.endswith('"')):
        return t[1:-1]
    return t


def _match_clause(val: Any, op: str, target) -> bool:
    s_val = "" if val is None else str(val)
    if op == "=":
        return s_val == str(target)
    if op == "!=":
        return s_val != str(target)
    if op == "in":
        if not isinstance(target, list):
            return False
        return s_val in [str(t) for t in target]
    if op == "startswith":
        return s_val.startswith(str(target))
    if op == "endswith":
        return s_val.endswith(str(target))
    if op == "contains":
        return str(target) in s_val
    if op == "~":
        try:
            return re.search(str(target), s_val) is not None
        except re.error:
            return False
    raise ValueError(f"unknown op {op!r}")


def _parse_filter(tokens: list[str]) -> list[tuple[str, str, Any]]:
    """Returns list of (field, op, target). Joined by AND."""
    out: list[tuple[str, str, Any]] = []
    i = 0
    while i < len(tokens):
        if tokens[i] == ",":
            i += 1
            continue
        field = tokens[i]
        op = tokens[i + 1]
        if op in ("=", "!=", "startswith", "endswith", "contains", "~"):
            target = _unquote(tokens[i + 2])
            out.append((field, op, target))
            i += 3
        elif op == "in":
            # consume `[a,b,c]`
            if tokens[i + 2] != "[":
                raise ValueError("expected `[` after `in`")
            j = i + 3
            items: list[str] = []
            while j < len(tokens) and tokens[j] != "]":
                if tokens[j] != ",":
                    items.append(_unquote(tokens[j]))
                j += 1
            if j == len(tokens):
                raise ValueError("missing `]`")
            out.append((field, "in", items))
            i = j + 1
        else:
            raise ValueError(f"unknown operator after {field!r}: {op!r}")
    return out


def query(report, expr: str) -> list[dict]:
    """Execute the filter expression against a ScanReport. Returns a list of
    matched findings as dicts. Available fields: severity, title, check_id,
    check_name, url, confidence."""
    expr = expr.strip()
    # Strip optional outer findings(...) wrapper for friendlier syntax
    m = re.match(r"^findings\s*\((.*)\)\s*$", expr, re.DOTALL)
    if m:
        expr = m.group(1)
    tokens = _tokenize(expr)
    clauses = _parse_filter(tokens) if tokens else []

    out: list[dict] = []
    for r in report.results:
        for f in r.findings:
            entry = {
                "severity": f.severity,
                "title": f.title,
                "check_id": r.check_id,
                "check_name": r.check_name,
                "url": f.url,
                "evidence_preview": (f.evidence or "")[:200],
            }
            if all(_match_clause(entry.get(field), op, target) for field, op, target in clauses):
                out.append(entry)
    return out
