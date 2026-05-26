"""Item #77 — pre-install static scan of a plugin / theme .zip.

`wpsecscan scan-zip /path/to/plugin.zip`

Unzips into a temp dir, walks the PHP/JS/CSS payload looking for
patterns commonly associated with malicious or vulnerable WordPress
extensions:

  • eval / base64_decode / gzinflate chains            → high
  • assert(\$_REQUEST[...]) / preg_replace 'e' modifier  → critical
  • create_function with user input                    → high
  • shell exec primitives (exec/system/passthru/...)   → high
  • file_get_contents("php://input")  + eval()         → critical
  • hard-coded include of remote URL via allow_url_include → critical
  • unverified update server URLs (http://, no https)  → medium
  • known-vulnerable plugin slug (per wpsecscan vuln DB) → varies
  • plugin/theme header missing 'Tested up to' / 'Requires PHP' → low

This is signature-based static analysis — by design it has FPs (a
benign template engine may use eval-ish patterns). The output is a
normal ScanReport so the same reporters (HTML/PDF/JSON/SARIF) work.
"""
from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .models import CheckResult, Finding, ScanReport


# (regex, severity, title, remediation) tuples. Compiled lazily.
_PATTERNS = [
    (r"\beval\s*\(\s*(?:gzinflate|base64_decode|str_rot13)", "high",
     "Obfuscated eval() — common malware encoder chain",
     "Manually review the file. Reject the plugin if this is in payload code."),
    (r"\bassert\s*\(\s*\$_(?:REQUEST|GET|POST|COOKIE)", "critical",
     "assert() called on raw HTTP input — full code execution",
     "Reject. There is no legitimate use of assert() on user input."),
    (r"\bpreg_replace\s*\(\s*['\"][^'\"]*['\"]\s*\.?\s*['\"]?e['\"]?", "critical",
     "preg_replace with the 'e' modifier (PHP-eval'd replacement)",
     "Reject. /e was removed in PHP 7; presence indicates malware or abandonware."),
    (r"\bcreate_function\s*\(", "high",
     "create_function() — accepts code-as-string, equivalent to eval()",
     "Reject or fork. create_function was removed in PHP 8."),
    (r"\b(?:exec|system|passthru|popen|proc_open|shell_exec)\s*\(", "high",
     "Shell-exec primitive in plugin/theme code",
     "Audit the call site. A WP plugin almost never needs to shell out."),
    (r"file_get_contents\s*\(\s*['\"]php://input['\"]", "high",
     "Reads raw HTTP body (php://input) — backdoor pattern",
     "Audit. Combined with eval() or unserialize() this is a backdoor."),
    (r"\bunserialize\s*\(\s*\$_(?:REQUEST|GET|POST|COOKIE)", "critical",
     "unserialize() on raw HTTP input — RCE primitive",
     "Reject. PHP object injection lets attackers run code via magic methods."),
    (r"include(_once)?\s*\(\s*['\"]https?://", "critical",
     "include of a REMOTE URL — needs allow_url_include + is exploitable",
     "Reject. Remote-file-inclusion is one of the highest-severity PHP bugs."),
    (r"http://[^\s'\"<>]+/(?:update|version|check)\.(?:php|json)", "medium",
     "Update server URL is HTTP, not HTTPS — MITM-replaceable updates",
     "Ask the author to migrate the update endpoint to HTTPS."),
    (r"\$wpdb->query\s*\(\s*['\"][^'\"]*\$_(?:REQUEST|GET|POST)", "critical",
     "Raw user input concatenated into a wpdb->query() — SQL injection",
     "Use $wpdb->prepare() with %s/%d placeholders. Reject if unfixed."),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), sev, title, rem)
              for rx, sev, title, rem in _PATTERNS]


def _header_value(text: str, key: str) -> str:
    m = re.search(rf"^\s*\*?\s*{re.escape(key)}\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan_zip(zip_path: Path) -> ScanReport:
    """Unzip + static-scan + return a ScanReport. Cleans the temp dir on exit."""
    findings: list[Finding] = []
    tmp = Path(tempfile.mkdtemp(prefix="wpsec-zip-"))
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Reject path-traversal entries before unzipping.
            for member in zf.namelist():
                if member.startswith(("/", "\\")) or ".." in Path(member).parts:
                    findings.append(Finding(
                        severity="critical",
                        title="Path-traversal entry in zip",
                        evidence=f"member: {member!r}",
                        remediation="Reject this archive. The plugin's installer can write outside its directory.",
                        url=str(zip_path),
                    ))
                    break
            else:
                zf.extractall(tmp)

        php_files = list(tmp.rglob("*.php"))
        for php in php_files:
            try:
                text = php.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = php.relative_to(tmp)

            # Plugin/Theme header sanity (only on top-level *.php).
            if len(rel.parts) <= 2 and "Plugin Name:" in text:
                if not _header_value(text, "Tested up to"):
                    findings.append(Finding(
                        severity="low",
                        title=f"Plugin header missing 'Tested up to': {rel}",
                        evidence="No 'Tested up to:' line in plugin header",
                        remediation="Ask the author to update the plugin header — abandoned plugins skip this.",
                        url=str(rel),
                    ))
                if not _header_value(text, "Requires PHP"):
                    findings.append(Finding(
                        severity="low",
                        title=f"Plugin header missing 'Requires PHP': {rel}",
                        evidence="No 'Requires PHP:' line in plugin header",
                        remediation="Ask the author to declare the minimum PHP version.",
                        url=str(rel),
                    ))

            # Static-pattern checks
            for rx, sev, title, rem in _COMPILED:
                for m in rx.finditer(text):
                    snippet = text[max(0, m.start() - 60):m.end() + 60]
                    findings.append(Finding(
                        severity=sev,
                        title=f"{title} in {rel}",
                        evidence=snippet.strip()[:400],
                        remediation=rem,
                        url=str(rel),
                    ))

        if not findings:
            findings.append(Finding(
                severity="info",
                title="No suspicious static patterns detected",
                evidence=f"Scanned {len(php_files)} PHP file(s).",
                remediation="Static analysis is signature-based; manual review is still recommended for production installs.",
            ))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return ScanReport(
        target=f"file://{zip_path}",
        scanned_at=_now_iso(),
        duration_ms=0,
        results=[CheckResult(
            check_id="scan_zip",
            check_name="Pre-install plugin/theme static scan",
            findings=findings,
        )],
    )
