"""When phpinfo() output is exposed, parse it for dangerous runtime flags.

The existing `exposed_files` check flags `phpinfo.php` / `info.php`
exposure. This check goes one step further: download the page and parse
the rendered phpinfo() table for dangerous `allow_url_include=On`,
`allow_url_fopen=On`, `display_errors=On`, and `expose_php=On` settings.
Each merits a separate finding because the remediation is different.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/test.php", "/php-info.php")

# Match `directive_name | value | value` table rows.
_ROW_RE = re.compile(
    r"<tr[^>]*>\s*<td[^>]*>([a-zA-Z_]+)</td>\s*<td[^>]*>([^<]+)</td>",
    re.IGNORECASE,
)

_DANGEROUS = {
    "allow_url_include": ("critical", "Direct RFI enabler — any `include $_GET['x']` becomes RCE"),
    "allow_url_fopen":   ("medium",   "SSRF prerequisite — file_get_contents() over HTTP"),
    "display_errors":    ("medium",   "PHP error messages leak server paths + framework versions to visitors"),
    "expose_php":        ("low",      "`X-Powered-By: PHP/x.y.z` header exposes precise PHP version"),
    "register_globals":  ("critical", "Ancient PHP4-era flag — every GET/POST becomes a global. Should not exist."),
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    text: str | None = None
    found_path = ""
    for p in _PHPINFO_PATHS:
        step(f"probing {p} for phpinfo output...")
        r = await client.get(p)
        if r is None or r.status_code != 200 or not r.text:
            continue
        if "phpinfo()" in r.text or "PHP Version" in r.text and "phpinfo" in r.text.lower():
            text = r.text
            found_path = p
            break
    if not text:
        return findings  # nothing exposed → nothing to parse
    parsed: dict[str, str] = {}
    for m in _ROW_RE.finditer(text):
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if key in _DANGEROUS and key not in parsed:
            parsed[key] = val
    for key, (sev, what) in _DANGEROUS.items():
        v = parsed.get(key, "")
        if v.lower() in ("on", "1", "true", "enabled"):
            findings.append(Finding(
                severity=sev,
                title=f"phpinfo exposes `{key} = {v}` — {what.split(' — ')[0]}",
                evidence=(
                    f"Parsed from {found_path}: {key} = {v}\n\n{what}"
                ),
                remediation=(
                    f"In php.ini (or .user.ini), set `{key} = Off`. Then verify with "
                    f"`php -i | grep {key}` or by reloading the (still-exposed) "
                    f"phpinfo page. After fixing, ALSO delete {found_path} from "
                    "the web root — leaving phpinfo public is itself a finding."
                ),
                url=client.url(found_path),
                extra={"directive": key, "value": v},
            ))
    return findings
