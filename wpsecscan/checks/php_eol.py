"""PHP version EOL audit.

Many WordPress sites silently run PHP versions that haven't received a
security patch in years. PHP's annual minor-release schedule means version
N is fully supported for 2 years, then receives security-only fixes for
1 more year — so anything older than ~3 years past its release date is
unsupported. Cross-references the detected PHP version against the
PHP-team's published end-of-life schedule.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..http import Client
from ..models import Finding


# https://www.php.net/supported-versions.php — security-fix end-of-life dates.
# Update annually. Anything earlier than 7.0 is folded into a single "ancient"
# bucket because it's been EOL for so long.
PHP_EOL: dict[str, str] = {
    "5.6":  "2018-12-31",
    "7.0":  "2018-12-03",
    "7.1":  "2019-12-01",
    "7.2":  "2020-11-30",
    "7.3":  "2021-12-06",
    "7.4":  "2022-11-28",
    "8.0":  "2023-11-26",
    "8.1":  "2025-12-31",
    "8.2":  "2026-12-08",
    "8.3":  "2027-12-31",
    "8.4":  "2028-12-31",
}

_PHP_VERSION_RE = re.compile(r"PHP[/\s]+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def _detect_php_version_from_headers(headers: dict) -> str | None:
    """Pull a PHP X.Y(.Z) version out of `Server` / `X-Powered-By`. Returns
    just the X.Y prefix because that's the granularity of EOL dates."""
    for hname in ("server", "x-powered-by"):
        v = headers.get(hname) or headers.get(hname.title()) or ""
        m = _PHP_VERSION_RE.search(v)
        if m:
            parts = m.group(1).split(".")
            return ".".join(parts[:2])  # X.Y
    return None


def _eol_finding(php_minor: str) -> tuple[str, str, str] | None:
    """Return (severity, title_suffix, detail) or None if version is supported."""
    eol_date = PHP_EOL.get(php_minor)
    if not eol_date:
        # Unknown / newer than table → assume supported.
        return None
    try:
        eol_dt = datetime.strptime(eol_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    days_past_eol = (now - eol_dt).days
    if days_past_eol < 0:
        # Still supported, but warn when within 90 days of EOL.
        if abs(days_past_eol) <= 90:
            return ("low", f"reaches EOL in {abs(days_past_eol)} days",
                    f"PHP {php_minor} reaches end-of-life on {eol_date}.")
        return None
    # Past EOL.
    if days_past_eol > 365:
        sev = "high"
    elif days_past_eol > 90:
        sev = "medium"
    else:
        sev = "low"
    yrs = days_past_eol / 365.25
    return (sev, f"end-of-life ({yrs:.1f} years past)",
            f"PHP {php_minor} reached end-of-life on {eol_date} — no further "
            "security fixes from the PHP team. Every CVE published since then "
            "remains unpatched on this server.")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching homepage to read Server/X-Powered-By...")
    r = await client.get("/")
    if r is None:
        return findings
    php = _detect_php_version_from_headers({k.lower(): v for k, v in r.headers.items()})
    if not php:
        findings.append(Finding(
            severity="info",
            title="PHP version not disclosed in response headers",
            evidence="Neither `Server` nor `X-Powered-By` revealed a PHP X.Y version.",
            remediation="No action — this is the safe configuration.",
            url=ctx["target"],
        ))
        return findings

    result = _eol_finding(php)
    if result is None:
        findings.append(Finding(
            severity="info",
            title=f"PHP {php} appears to be a supported release",
            evidence=f"Detected via response header; latest EOL data through 8.4.",
            remediation="No action — but verify against https://www.php.net/supported-versions.php.",
            url=ctx["target"],
            extra={"php_version": php},
        ))
        return findings

    sev, suffix, detail = result
    findings.append(Finding(
        severity=sev,
        title=f"PHP {php} {suffix}",
        evidence=(
            f"{detail}\n"
            f"Detected via: {r.headers.get('Server', r.headers.get('X-Powered-By', '(unknown)'))}"
        ),
        remediation=(
            "Upgrade to a supported PHP version (8.2+ as of 2026). Most managed "
            "WordPress hosts let you switch in the control panel; self-hosted "
            "sites need an OS package update + a PHP-FPM/Apache module swap. "
            "Verify your plugins/themes claim compatibility with the target "
            "version before flipping the switch in production."
        ),
        url=ctx["target"],
        extra={"php_version": php, "eol_date": PHP_EOL.get(php)},
    ))
    return findings
