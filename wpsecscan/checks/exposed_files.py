from __future__ import annotations

import sys
from pathlib import Path

from ..http import Client
from ..models import Finding

# When bundled by PyInstaller, data files live under sys._MEIPASS.
def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent.parent / "data"


def _load_paths() -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    f = _data_dir() / "known_paths.txt"
    if not f.exists():
        return out
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 3:
            continue
        path, sev, label = parts
        out.append((path.strip(), sev.strip(), label.strip()))
    return out


def _looks_real(content_type: str, body: str, path: str) -> bool:
    """Avoid false positives from SPAs that 200 every path with index.html."""
    if "text/html" in content_type and "<!doctype html>" in body.lower()[:200]:
        # Heuristic: a 200 HTML on /.env or /wp-config.php.bak is almost certainly
        # a soft-404. Be strict for high-risk paths.
        risky = (".env", ".bak", ".sql", "wp-config", "debug.log", ".git/", "phpinfo", "info.php", "adminer", ".htaccess")
        if any(r in path.lower() for r in risky):
            return False
    return True


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    paths = _load_paths()
    if not paths:
        findings.append(
            Finding(
                severity="info",
                title="Exposed-files probe list missing",
                evidence="known_paths.txt not found in bundle.",
                remediation="Rebuild the scanner — the data file did not ship with the binary.",
            )
        )
        return findings

    for path, sev, label in paths:
        step(f"probing /{path}...")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        body = r.text or "" if hasattr(r, "text") else ""
        ct = r.headers.get("content-type", "")
        if not _looks_real(ct, body, path):
            continue
        snippet = (body[:200].replace("\n", " ") + "...") if body else f"(binary, {len(r.content)} bytes)"
        findings.append(
            Finding(
                severity=sev,
                title=f"Exposed: {label} at /{path}",
                evidence=f"GET /{path} → 200 ({ct or 'unknown content-type'})\n  preview: {snippet}",
                remediation=(
                    f"Remove /{path} from the document root immediately, or add a server-level deny rule. "
                    "For backups/secrets, also rotate any credentials they contained — assume they are compromised."
                ),
                url=client.url("/" + path),
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No high-risk exposed files found",
                evidence=f"Probed {len(paths)} known-bad paths; none returned 200.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
