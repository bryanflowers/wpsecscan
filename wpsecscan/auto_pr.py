"""N41 Auto-PR with the fix.

For a small set of well-known config misfires (missing HSTS, weak CSP,
exposed wp-config backup, missing X-Frame-Options), generate:
  1. the exact patch text to apply
  2. a copy-paste `gh pr create` command to open a PR with that patch

We never actually call gh — the user reviews the patch + posts intentionally.

The fix templates are conservative: they only touch nginx/apache/.htaccess/
wp-config; they don't attempt to modify plugin code.
"""
from __future__ import annotations

from .models import ScanReport, SEVERITY_RANK


# check_id -> (patch_text, target_file, commit_message)
FIX_TEMPLATES = {
    "tls_headers": {
        "patch": (
            "# Add to your nginx server { } block:\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;\n"
        ),
        "file": "nginx.conf",
        "msg": "security: add HSTS + content-type-options + referrer-policy",
    },
    "csp": {
        "patch": (
            "# Add a starter CSP. Tune to your asset hosts.\n"
            "add_header Content-Security-Policy "
            "\"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\" always;\n"
        ),
        "file": "nginx.conf",
        "msg": "security: add Content-Security-Policy header",
    },
    "exposed_files": {
        "patch": (
            "# Block accidentally-exposed sensitive files:\n"
            "location ~ /\\.(env|git|svn|hg|DS_Store) { deny all; }\n"
            "location ~ \\.(bak|swp|tmp|orig|save|old|copy)$ { deny all; }\n"
            "location = /wp-config.php { deny all; }\n"
        ),
        "file": "nginx.conf",
        "msg": "security: deny exposed config / backup files",
    },
    "backup_file_fuzz": {
        "patch": (
            "location ~ \\.(bak|swp|tmp|orig|save|old|copy|disabled|dev|staging|production)$ { deny all; }\n"
            "location ~ /\\.(git|vscode|idea|DS_Store|svn) { deny all; }\n"
        ),
        "file": "nginx.conf",
        "msg": "security: deny editor / IDE backup files",
    },
    "directory_listing": {
        "patch": "# Disable directory autoindex globally:\nautoindex off;\n",
        "file": "nginx.conf",
        "msg": "security: disable directory autoindex",
    },
    "cors": {
        "patch": (
            "# Replace any `Access-Control-Allow-Origin *` with an allow-list.\n"
            "# Example for a single trusted SPA origin:\n"
            "add_header Access-Control-Allow-Origin \"https://app.example.com\" always;\n"
            "add_header Access-Control-Allow-Credentials \"true\" always;\n"
        ),
        "file": "nginx.conf",
        "msg": "security: tighten CORS to explicit origin allow-list",
    },
    "debug_leaks": {
        "patch": (
            "# Add to wp-config.php to stop debug output reaching responses:\n"
            "define('WP_DEBUG_DISPLAY', false);\n"
            "@ini_set('display_errors', 0);\n"
            "define('WP_DEBUG_LOG', true);  // log to wp-content/debug.log instead\n"
        ),
        "file": "wp-config.php",
        "msg": "security: suppress WP_DEBUG output in responses",
    },
    "cookies": {
        "patch": (
            "# In nginx, add the Secure / HttpOnly flags to forwarded cookies:\n"
            "proxy_cookie_flags ~ secure samesite=strict httponly;\n"
        ),
        "file": "nginx.conf",
        "msg": "security: add Secure + HttpOnly + SameSite=Strict to cookies",
    },
}


def fixes_for(report: ScanReport, *, min_sev: str = "medium") -> list[dict]:
    """Return list of {check_id, patch, file, msg, finding_title} for every
    finding ≥ min_sev that has a fix template."""
    threshold = SEVERITY_RANK.get(min_sev, 2)
    seen: set[str] = set()
    out: list[dict] = []
    for r in report.results:
        if r.check_id in seen or r.check_id not in FIX_TEMPLATES:
            continue
        for f in r.findings:
            if SEVERITY_RANK.get(f.severity, -1) < threshold:
                continue
            template = FIX_TEMPLATES[r.check_id]
            out.append({
                "check_id": r.check_id,
                "patch": template["patch"],
                "file": template["file"],
                "msg": template["msg"],
                "finding_title": f.title,
                "severity": f.severity,
            })
            seen.add(r.check_id)
            break
    return out


def gh_commands(report: ScanReport, *, repo: str, branch_prefix: str = "wpsec-fix",
                min_sev: str = "medium") -> list[str]:
    """Build a single shell script's worth of `gh` + `git` commands.
    User runs them manually after reviewing each patch.

    repo: 'owner/name'
    """
    fixes = fixes_for(report, min_sev=min_sev)
    if not fixes:
        return ["# No fixable findings at the chosen severity threshold."]

    lines = [
        "#!/usr/bin/env bash",
        "# WPSecScan auto-PR helper. REVIEW each patch before running.",
        "set -euo pipefail",
        "",
        "git fetch origin",
        f"git switch -c {branch_prefix}-$(date +%Y%m%d-%H%M) origin/main",
        "",
    ]
    for f in fixes:
        # Embed patch as a here-doc so it doesn't get shell-mangled
        lines.extend([
            f"# --- Fix for {f['check_id']} ({f['severity']}): {f['finding_title'][:60]} ---",
            f"cat >> {f['file']} <<'EOF'",
            f["patch"].rstrip(),
            "EOF",
            f"git add {f['file']}",
            f"git commit -m \"{f['msg']}\"",
            "",
        ])

    lines.extend([
        f"git push -u origin HEAD",
        f"gh pr create --repo {repo} --title 'security: WPSecScan-suggested config hardening' \\",
        f"  --body 'Generated from a WPSecScan report. Each commit corresponds to a single check ID.\\nReview each patch carefully — these are conservative defaults, not site-specific tuning.'",
    ])
    return lines


def write_script(report: ScanReport, path, *, repo: str, min_sev: str = "medium") -> None:
    """Write the shell script to disk."""
    from pathlib import Path
    fixes = fixes_for(report, min_sev=min_sev)
    Path(path).write_text("\n".join(gh_commands(report, repo=repo, min_sev=min_sev)),
                          encoding="utf-8")
    try:
        from . import activity as _act
        _act.emit("artifact", f"auto-PR script: {len(fixes)} fix(es) → {Path(path).name}")
    except ImportError:
        pass


# C50 (v2.7.0) — for one-liner fixes (.htaccess / wp-config.php / header.php),
# write a unified-diff patch alongside the shell script so the operator can
# `git apply` directly instead of pasting `gh` commands.

_ONE_LINER_HINT_FILES = ("wp-config.php", ".htaccess", "wp-content/themes/*/header.php",
                          "wp-content/themes/*/functions.php")


def _looks_like_one_liner(finding) -> bool:
    """Heuristic: the remediation field references a single config file?"""
    rem = (finding.remediation or "").lower()
    return any(p.split("/")[-1].lower() in rem for p in _ONE_LINER_HINT_FILES)


def write_one_liner_patches(report: ScanReport, out_dir, *, min_sev: str = "medium") -> int:
    """C50 — for each one-liner-fixable finding, ask the AI to draft a
    unified diff + write `<out_dir>/<check_id>-<idx>-fix.patch`. Returns
    the count of patches written. No-op if no AI backend or no matches."""
    from pathlib import Path
    try:
        from . import ai_assist as _ai
    except ImportError:
        return 0
    if not _ai.is_configured():
        return 0
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_n = sev_rank.get(min_sev, 2)
    n = 0
    for r in report.results:
        for idx, f in enumerate(r.findings):
            if sev_rank.get(f.severity, 0) < min_n:
                continue
            if not _looks_like_one_liner(f):
                continue
            diff = _ai.fix_pr_diff(f)
            if not diff or len(diff) < 30:
                continue
            patch_path = out_dir / f"{r.check_id}-{idx}-fix.patch"
            body_path  = out_dir / f"{r.check_id}-{idx}-fix.md"
            patch_path.write_text(diff + "\n", encoding="utf-8")
            body = _ai.fix_pr_body(f)
            if body:
                body_path.write_text(body + "\n", encoding="utf-8")
            n += 1
    return n
