"""J22 Crash auto-submit helper.

When a scan crashes, we already write a crash report to ~/.wpsecscan/crash-*.txt.
This module adds a one-step "submit" helper: it builds a pre-filled GitHub
Issues URL containing the redacted crash log so the user just clicks once.

We deliberately don't auto-POST — the user reviews the redacted log before
filing.
"""
from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

REPO = "bryanflowers/wpsecscan"  # change if you fork — must match the GitHub repo path

# Patterns that look like secrets / tokens — replace with [REDACTED]
_REDACT_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*['\"]?bearer\s+)[A-Za-z0-9._\-]{20,}"),
    re.compile(r"(?i)(api[-_]?key\s*[:=]\s*['\"]?)[A-Za-z0-9._\-]{20,}"),
    re.compile(r"(?i)(password\s*[:=]\s*['\"]?)[^\s'\"]+"),
    re.compile(r"(?i)(token\s*[:=]\s*['\"]?)[A-Za-z0-9._\-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),                  # AWS access keys
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),              # GitHub PAT (classic)
    re.compile(r"github_pat_[A-Za-z0-9_]{60,}"),      # GitHub PAT (fine-grained)
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),          # Stripe live key
    re.compile(r"(?i)\bemail\s*[:=]\s*['\"]?[^\s'\"@]+@[^\s'\"]+"),
]


def redact(text: str) -> str:
    """Run every redaction pattern over the text. Returns the cleaned string."""
    out = text
    for pat in _REDACT_PATTERNS:
        try:
            if pat.groups:
                out = pat.sub(lambda m: m.group(1) + "[REDACTED]", out)
            else:
                out = pat.sub("[REDACTED]", out)
        except (re.error, IndexError):
            continue
    return out


def build_submit_url(crash_log_path: Path, *, version: str = "?") -> str:
    """Build a GitHub Issues `new` URL with the (redacted) crash log
    pre-filled in the body."""
    try:
        log_text = crash_log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log_text = "(crash log not readable)"
    log_text = redact(log_text)
    log_text = log_text[-6000:]  # GH issue URL has practical length limits

    title = f"[Crash report] WPSecScan v{version}"
    body = (
        "**WPSecScan version:** " + version + "\n"
        "**OS:** (please fill in: Windows / macOS / Linux + version)\n"
        "**How triggered:** (please describe)\n\n"
        "## Crash log (redacted)\n```\n" + log_text + "\n```\n\n"
        "_Submitted via the in-app crash helper._"
    )
    params = urllib.parse.urlencode({
        "title": title,
        "body": body,
        "labels": "crash,auto-submitted",
    })
    return f"https://github.com/{REPO}/issues/new?{params}"
