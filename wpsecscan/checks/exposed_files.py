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


def _looks_real(content_type: str, body: str, path: str, home_body: str = "") -> bool:
    """Avoid false positives from SPAs / WP rewrite catch-alls that 200 every
    path with the homepage HTML.

    Returns True iff the response looks like the actual targeted resource,
    not a soft-404. Strategy:
      1. If the response is binary or non-HTML, trust it.
      2. If the response is HTML AND the path has a structural extension
         (.env, .sql, .bak, .php~, .git, .htaccess), trust the extension
         and reject HTML — a real `.env` is plain text, not `<!doctype html>`.
      3. If HTML and we have a homepage body for comparison, soft-404 the
         response when its body is identical or near-identical to the home
         page (length within 5% AND first 200 chars match).
    """
    body_lower = body.lower()[:500]
    is_html = "text/html" in content_type or "<!doctype html>" in body_lower or "<html" in body_lower
    if not is_html:
        return True
    # Structural extensions whose real content is not HTML
    structural = (".env", ".bak", ".sql", "wp-config", "debug.log", ".git/", "phpinfo",
                  "info.php", "adminer", ".htaccess", ".swp", ".orig", ".sqlite",
                  ".tar.gz", ".zip", ".json", ".yaml", ".yml")
    if any(r in path.lower() for r in structural):
        return False
    # WP rewrite catch-all detection — soft-404 if body matches homepage
    if home_body and body:
        if abs(len(body) - len(home_body)) < max(200, len(home_body) // 20) \
                and body[:200] == home_body[:200]:
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

    # Fetch the homepage once so _looks_real can detect WP catch-all soft-404s
    # by comparing each probe response to it.
    home_body = ""
    home_r = await client.get("/")
    if home_r is not None and home_r.text:
        home_body = home_r.text

    for path, sev, label in paths:
        step(f"probing /{path}...")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        body = r.text or "" if hasattr(r, "text") else ""
        ct = r.headers.get("content-type", "")
        if not _looks_real(ct, body, path, home_body):
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
