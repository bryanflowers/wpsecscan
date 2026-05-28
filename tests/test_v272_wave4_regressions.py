"""Regression tests for v2.7.2 Wave 4 — Low-severity code-quality.

C18 auth-debug body redaction (mask_private piped through response body)
C19 ua_rotation uses secrets.choice not random.choice
C20 perf/_legacy.py memo cache key switched SHA-1 → SHA-256
C21 push_gcp_scc logs swallowed exceptions to stderr
"""
import inspect


def _strip(src: str) -> str:
    """Strip line-comments + docstrings before pattern matching."""
    import re as _re
    out, in_doc, mark = [], False, None
    for line in src.splitlines():
        s = line.lstrip()
        if not in_doc and (s.startswith('"""') or s.startswith("'''")):
            mark = s[:3]
            if s.count(mark) >= 2 and len(s) > 3:
                continue
            in_doc = True
            continue
        if in_doc:
            if mark in line:
                in_doc = False
            continue
        line = _re.sub(r"\s+#.*$", "", line)
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# C18 — auth-debug body redaction
# ---------------------------------------------------------------------------

def test_auth_debug_log_pipes_body_through_mask_private():
    """Source check on the module file directly: the auth-debug log
    helper must pipe the response body through mask_private. We read
    the file rather than inspect.getsource because the module-level
    `check` symbol is re-exported as `authenticated` in __init__.py."""
    from pathlib import Path
    import wpsecscan
    pkg_root = Path(wpsecscan.__file__).parent
    text = (pkg_root / "checks" / "authenticated.py").read_text(encoding="utf-8")
    assert "from ..ai_safety import mask_private" in text
    assert "_mask((response.text or \"\")[:500])" in text


# ---------------------------------------------------------------------------
# C19 — ua_rotation uses secrets.choice
# ---------------------------------------------------------------------------

def test_ua_rotation_uses_secrets_not_random():
    from wpsecscan import ua_rotation
    src = _strip(inspect.getsource(ua_rotation))
    assert "secrets.choice" in src
    assert "random.choice" not in src


# ---------------------------------------------------------------------------
# C20 — memo cache uses SHA-256
# ---------------------------------------------------------------------------

def test_legacy_memo_uses_sha256_not_sha1():
    from wpsecscan.perf import _legacy
    src = _strip(inspect.getsource(_legacy))
    assert "hashlib.sha1" not in src, (
        "v2.7.2 C20 — memoize_check / lookup_memo must use SHA-256, "
        "not SHA-1 (collision risk + 16-hex truncation worsened it)."
    )
    assert "hashlib.sha256" in src


# ---------------------------------------------------------------------------
# C21 — gcp_scc logs swallowed exceptions
# ---------------------------------------------------------------------------

def test_gcp_scc_logs_swallowed_exceptions():
    from wpsecscan import integrations_v27
    src = _strip(inspect.getsource(integrations_v27.push_gcp_scc))
    # The new pattern: catch + print to stderr (not bare `except: continue`).
    assert "except Exception as _exc" in src
    assert "stderr" in src
