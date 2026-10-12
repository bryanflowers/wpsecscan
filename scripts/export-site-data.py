#!/usr/bin/env python3
"""Export the numbers the wpsecscan.com website shows, computed from code.

Writes two files into a checkout of the website repo:

  <site>/src/data/checks.json   per-check rows grouped into display categories
  <site>/src/data/release.json  version / counts / URLs used by every page

Every count comes from this repository (check registry, argparse help text,
dispatch tables, data files, CHANGELOG, pyproject.toml). Nothing is typed in
by hand except the two literals flagged below (``EXE_SIZE_MB`` and
``LICENSE_ID``).

Usage:
    python scripts/export-site-data.py --site-dir <path-to-website-repo>
    python scripts/export-site-data.py --site-dir <path> --check   # CI: exit 1 on drift

``--check`` compares the parsed JSON on disk with what would be generated and
ignores ``_generated_from.commit`` (it changes on every commit, so including
it would make the check fail the moment the generated files are committed).

Display categories in checks.json keep the curation already present in the
site's existing checks.json; check ids it has never seen are slotted in by the
keyword heuristic below.

Stdlib only; Python 3.10+.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Importing the package must never touch the network.
os.environ.setdefault("WPSECSCAN_NO_LIVE", "1")

# Measured from the v2.9.0 release assets (wpsecscan.exe / wpsecscan-gui.exe are
# ~22 MB each); not derivable from source. Update when the assets change size.
EXE_SIZE_MB = 22
LICENSE_ID = "AGPL-3.0-or-later"
REPO_SLUG = "bryanflowers/wpsecscan"

# Sub-key of the compliance data files -> display name. Order is the order the
# website lists them in.
_FRAMEWORK_NAMES: dict[str, str] = {
    "pci_dss": "PCI-DSS 4.0",
    "nist_800_53": "NIST 800-53",
    "iso_27001": "ISO 27001",
    "iso_27001_2022": "ISO 27001:2022",
    "nist_csf": "NIST CSF 2.0",
    "cis_v8": "CIS v8",
    "hitrust": "HITRUST",
    "cmmc": "CMMC 2.0",
    "hipaa": "HIPAA",
    "soc2": "SOC 2",
    "fedramp": "FedRAMP",
    "gdpr": "GDPR",
}
# Present in compliance_extra.json for a single check only; not a
# check-level framework mapping, so it is not counted or listed.
_FRAMEWORKS_EXCLUDED = {"ferpa"}
_COMPLIANCE_FILES = ("compliance_map.json", "compliance_v2.json", "compliance_extra.json")

# ---------------------------------------------------------------------------
# Category fallback heuristic for check IDs not in the existing curation.
# Ordered: first match wins. (Moved here from the website's gen-checks-json.py.)
# ---------------------------------------------------------------------------
_HEURISTIC: list[tuple[str, list[str]]] = [
    ("Authentication & session", [
        "login", "auth", "password", "mfa", "sso", "session", "jwt",
        "oauth", "webauthn", "passkey", "totp", "saml", "rbac",
        "app_password", "creds",
    ]),
    ("Transport & headers", [
        "tls", "headers", "csp", "cors", "cookie", "hsts", "ct_log",
        "mixed_content", "referrer", "permissions_policy",
    ]),
    ("File & directory exposure", [
        "exposed", "backup", "directory", "uploads", "source_map",
        "phpinfo", "wp_debug", "wpconfig", "trellis", "package_lock",
        "yarn_pnpm", "composer", "helm", "github_actions", "env_var",
        "favicon",
    ]),
    ("Injection & client-side", [
        "xss", "sqli", "ssti", "nosql", "csrf", "crlf", "hpp",
        "interactivity", "magecart", "skimmer", "ssrf_dom",
        "prototype_pollution", "search_highlight",
        "global_styles_css", "css_injection",
    ]),
    ("SSRF / RCE / open access", [
        "ssrf", "rce", "open_red", "redirect_chain", "file_upload",
        "upload_bypass", "xxe", "smuggling", "cloud_metadata",
        "wp_remote_get", "form_builder_upload",
    ]),
    ("GraphQL & APIs", [
        "graphql", "wpgraphql", "rest", "ajax", "wp_rest", "mcp",
        "api_key", "headless", "interactivity_api_state",
        "block_bindings", "synced_pattern", "rest_only_admin",
        "stripe_connect", "wc_stores_api",
    ]),
    ("DNS, email & infra", [
        "dns", "subdomain", "sendmail", "spf", "dmarc", "dkim",
        "smtp", "host_header", "hostname_collision",
        "cloudflare_origin", "host_platform", "service_exposure",
        "service_worker", "pwa_service_worker",
    ]),
    ("WordPress core, plugins & themes", [
        "core_cves", "core_checksums", "core_tampering",
        "plugin", "theme", "page_builder", "wp_form",
        "wp_membership", "wp_builder", "wp_commerce", "wpscan",
        "wp_fork", "wp_cli", "wp_cron", "wpcron",
        "wp_engine", "wp_playground", "fork_detection",
        "object_cache", "heartbeat", "amp_transitional",
        "wp_mail_smtp", "wp_debug_display_via_rest",
        "translation_plugin", "users", "open_registration",
        "wc_", "woo", "woocommerce", "stripe_webhook",
        "activitypub", "speculation_rules", "html_api_csp",
        "font_library", "block_style_variations",
        "companion_v", "core_tampering", "core_version",
    ]),
    ("Privacy, compliance & accessibility", [
        "a11y", "gdpr", "cookie_consent", "privacy", "tracking",
        "tracker", "tag_manager", "gtm", "rum",
        "ai_safety", "ai_agent", "ai_chatbot", "ai_plugin",
        "compliance", "email_obfuscation", "data_liberation",
    ]),
    ("Discovery & enumeration", [
        "discover", "enum", "fingerprint", "fork", "version",
        "vercel_preview", "host_platform", "perf",
        "github_leak", "ssh_audit", "robots_sitemap",
        "well_known", "security_txt", "subdomains",
        "abuseipdb", "vt", "greynoise", "shadow_takeover",
        "bucket", "s3", "referenced_buckets", "advisory",
        "ct_log_recent", "ct_log_shadow", "hibp",
    ]),
]


def _category_for(check_id: str, check_name: str, existing_map: dict[str, str]) -> str:
    """Return the category for a check, preferring human curation."""
    if check_id in existing_map:
        return existing_map[check_id]
    blob = f"{check_id} {check_name}".lower()
    for cat, keywords in _HEURISTIC:
        if any(k in blob for k in keywords):
            return cat
    return "Other"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _function_body(src: str, name: str) -> str:
    """Source text of top-level ``def <name>(`` up to the next top-level def."""
    m = re.search(rf"^def {re.escape(name)}\(.*?(?=^def |\Z)", src, re.S | re.M)
    if not m:
        raise SystemExit(f"export-site-data: cannot find def {name}() in __main__.py")
    return m.group(0)


# ---------------------------------------------------------------------------
# checks.json
# ---------------------------------------------------------------------------
def build_checks(site_dir: Path) -> dict[str, Any]:
    from wpsecscan.checks import ALL_CHECKS

    data_dir = ROOT / "wpsecscan" / "data"
    tags_path = data_dir / "check_tags.json"
    compliance_path = data_dir / "compliance_map.json"
    tags = _read_json(tags_path) if tags_path.exists() else {}
    compliance = _read_json(compliance_path) if compliance_path.exists() else {}

    # Existing curation + category order from the site's current checks.json.
    out_path = site_dir / "src" / "data" / "checks.json"
    existing_map: dict[str, str] = {}
    cat_order: list[str] = []
    if out_path.exists():
        try:
            prior = _read_json(out_path)
            for cat in prior.get("categories", []):
                cat_order.append(cat["name"])
                for ck in cat.get("checks", []):
                    if ck.get("id"):
                        existing_map[ck["id"]] = cat["name"]
        except (OSError, ValueError, KeyError, AttributeError):
            existing_map, cat_order = {}, []
    if "Other" not in cat_order:
        cat_order.append("Other")
    buckets: dict[str, list[dict[str, Any]]] = {c: [] for c in cat_order}

    total = 0
    aggressive = 0
    for cid, cname, _fn, agg in ALL_CHECKS:
        # 'authenticated' is the credentialed-scan driver, not a user-facing check.
        if cid == "authenticated":
            continue
        total += 1
        if agg:
            aggressive += 1
        t = tags.get(cid) or {}
        c = compliance.get(cid) or {}
        entry = {
            "id": cid,
            "name": cname,
            "aggressive": bool(agg),
            "owasp": t.get("owasp", "") or "",
            "owasp_label": t.get("owasp_label", "") or "",
            "attack": t.get("attack", "") or "",
            "attack_label": t.get("attack_label", "") or "",
            "cwe": t.get("cwe", "") or "",
            "d3fend": t.get("d3fend", "") or "",
            "pci_dss": c.get("pci_dss", "") or "",
            "nist_800_53": c.get("nist_800_53", "") or "",
            "iso_27001": c.get("iso_27001", "") or "",
        }
        bucket = _category_for(cid, cname, existing_map)
        if bucket not in buckets:
            buckets[bucket] = []
            cat_order.append(bucket)
        buckets[bucket].append(entry)

    categories = [
        {"name": name, "count": len(buckets[name]), "checks": buckets[name]}
        for name in cat_order
        if buckets[name]  # drop empty buckets
    ]
    return {
        "_total": total,
        "_aggressive_count": aggressive,
        "_generated_from": _generated_from(),
        "categories": categories,
    }


# ---------------------------------------------------------------------------
# release.json
# ---------------------------------------------------------------------------
def _pyproject() -> tuple[str, str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    ver = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    req = re.search(r'^requires-python\s*=\s*"([^"]+)"', text, re.M)
    if not ver or not req:
        raise SystemExit("export-site-data: version / requires-python not found in pyproject.toml")
    pymin = re.search(r"(\d+\.\d+)", req.group(1))
    if not pymin:
        raise SystemExit(f"export-site-data: cannot parse requires-python {req.group(1)!r}")
    return ver.group(1), pymin.group(1)


def _generated_from() -> dict[str, str]:
    version, _ = _pyproject()
    commit = "unknown"
    try:
        res = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            commit = res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return {"version": version, "commit": commit}


def _release_date(version: str) -> tuple[str, str | None]:
    """(date, date_source). date_source is None when the date comes from the CHANGELOG."""
    changelog = ROOT / "CHANGELOG.md"
    if changelog.exists():
        text = changelog.read_text(encoding="utf-8")
        m = re.search(
            rf"^## \[v{re.escape(version)}\]\s*[—–-]\s*(\d{{4}}-\d{{2}}-\d{{2}})",
            text, re.M,
        )
        if m:
            return m.group(1), None
    today = datetime.date.today().isoformat()
    return today, f"fallback: today's date (no CHANGELOG.md heading for v{version})"


def _format_list(main_src: str) -> list[str]:
    m = re.search(r'Supported:\s*"\s*"([A-Za-z0-9,\-]+)', main_src)
    if not m:
        raise SystemExit("export-site-data: cannot find the --format 'Supported:' list in __main__.py")
    return [x for x in m.group(1).split(",") if x]


def _push_providers(main_src: str) -> list[str]:
    body = _function_body(main_src, "_cmd_push")
    m = re.search(r"dispatch: dict\[str, tuple\[str, str\]\] = \{(.*?)\n    \}", body, re.S)
    if not m:
        raise SystemExit("export-site-data: cannot find the push dispatch dict in _cmd_push()")
    return re.findall(r'^\s+"([\w-]+)":\s*\(', m.group(1), re.M)


def _ai_helpers(main_src: str) -> list[str]:
    body = _function_body(main_src, "_cmd_ai")
    seen: list[str] = []
    for name in re.findall(r'\bsub == "([\w-]+)"', body):
        if name not in seen:
            seen.append(name)
    return seen


def _compliance_list() -> list[str]:
    data_dir = ROOT / "wpsecscan" / "data"
    keys: set[str] = set()
    for fname in _COMPLIANCE_FILES:
        for k, v in _read_json(data_dir / fname).items():
            if isinstance(v, dict) and not k.startswith("_"):
                keys.update(v)
    keys -= _FRAMEWORKS_EXCLUDED
    ordered = [k for k in _FRAMEWORK_NAMES if k in keys]
    # A framework that appears in the data but has no display name still counts.
    ordered += sorted(keys - set(_FRAMEWORK_NAMES))
    return [_FRAMEWORK_NAMES.get(k, k) for k in ordered]


def _feed_sources() -> int:
    src = (ROOT / "scripts" / "aggregate-cve-feed.py").read_text(encoding="utf-8")
    m = re.search(r"^SOURCES\s*=\s*\{(.*?)^\}", src, re.S | re.M)
    if not m:
        raise SystemExit("export-site-data: cannot find SOURCES dict in aggregate-cve-feed.py")
    return len(re.findall(r'^\s+"[\w-]+"\s*:\s*\w+', m.group(1), re.M))


def _threat_intel_providers() -> int:
    src = (ROOT / "wpsecscan" / "threat_intel_v2.py").read_text(encoding="utf-8")
    doc = re.match(r'\s*"""(.*?)"""', src, re.S)
    if not doc:
        raise SystemExit("export-site-data: threat_intel_v2.py has no module docstring")
    return len(re.findall(r"^#\d+\s+\w+", doc.group(1), re.M))


def build_release(checks: dict[str, Any]) -> dict[str, Any]:
    import wpsecscan.__main__ as cli
    from wpsecscan.checks import ALL_CHECKS
    from wpsecscan.prove import PROVERS

    version, python_min = _pyproject()
    tag = f"v{version}"
    date, date_source = _release_date(version)
    main_src = (ROOT / "wpsecscan" / "__main__.py").read_text(encoding="utf-8")
    formats = _format_list(main_src)
    compliance = _compliance_list()
    base = f"https://github.com/{REPO_SLUG}/releases"

    out: dict[str, Any] = {"version": version, "tag": tag, "date": date}
    if date_source:
        out["date_source"] = date_source
    out.update({
        "checks": checks["_total"],
        "checks_total": len(ALL_CHECKS),
        "aggressive": checks["_aggressive_count"],
        "categories": len(checks["categories"]),
        "subcommands": len(cli.SUBCOMMAND_HELP),
        "formats": len(formats),
        "format_list": formats,
        "emit_formats": len(cli._EMIT_DISPATCH),
        "push_providers": len(_push_providers(main_src)),
        "ai_helpers": len(_ai_helpers(main_src)),
        "proof_helpers": len(PROVERS),
        "compliance_frameworks": len(compliance),
        "compliance_list": compliance,
        "feed_sources_configured": _feed_sources(),
        "threat_intel_providers": _threat_intel_providers(),
        "python_min": python_min,
        "exe_size_mb": EXE_SIZE_MB,
        "license": LICENSE_ID,
        "release_url": f"{base}/tag/{tag}",
        "pypi_url": "https://pypi.org/project/wpsecscan/",
        "assets": {
            "exe": f"{base}/download/{tag}/wpsecscan.exe",
            "gui_exe": f"{base}/download/{tag}/wpsecscan-gui.exe",
            "wheel": f"{base}/download/{tag}/wpsecscan-{version}-py3-none-any.whl",
            "sdist": f"{base}/download/{tag}/wpsecscan-{version}.tar.gz",
            "sha256sums": f"{base}/download/{tag}/SHA256SUMS.txt",
            "sbom": f"{base}/download/{tag}/sbom.cyclonedx.json",
        },
    })
    return out


# ---------------------------------------------------------------------------
def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=2) + "\n"


def _comparable(obj: Any) -> Any:
    """Parsed JSON with the always-changing commit hash blanked out."""
    if isinstance(obj, dict) and isinstance(obj.get("_generated_from"), dict):
        obj = dict(obj)
        obj["_generated_from"] = {**obj["_generated_from"], "commit": None}
    return obj


def generate(site_dir: Path) -> dict[str, str]:
    """Return {relative path under site dir: file text} for both outputs."""
    checks = build_checks(site_dir)
    release = build_release(checks)
    return {
        "src/data/checks.json": _dump(checks),
        "src/data/release.json": _dump(release),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--site-dir", required=True, type=Path,
                    help="path to the wpsecscan.com website checkout")
    ap.add_argument("--check", action="store_true",
                    help="write nothing; exit 1 if the files on disk differ from what would be generated")
    args = ap.parse_args(argv)

    site_dir: Path = args.site_dir.resolve()
    if not site_dir.is_dir():
        print(f"export-site-data: --site-dir {site_dir} is not a directory", file=sys.stderr)
        return 2

    files = generate(site_dir)

    if args.check:
        drift = []
        for rel, text in files.items():
            path = site_dir / rel
            try:
                on_disk = _comparable(_read_json(path))
            except (OSError, ValueError):
                drift.append(f"{rel}: missing or not valid JSON")
                continue
            if on_disk != _comparable(json.loads(text)):
                drift.append(f"{rel}: differs from generated output")
        if drift:
            for line in drift:
                print(f"DRIFT {line}", file=sys.stderr)
            print("re-run: python scripts/export-site-data.py --site-dir <site>", file=sys.stderr)
            return 1
        print("site data up to date: " + ", ".join(files))
        return 0

    for rel, text in files.items():
        path = site_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))  # bytes: keep LF on Windows
        print(f"wrote {path}")
    checks = json.loads(files["src/data/checks.json"])
    release = json.loads(files["src/data/release.json"])
    print(f"  version {release['version']}  checks {release['checks']}/{release['checks_total']}  "
          f"aggressive {release['aggressive']}  categories {release['categories']}")
    for cat in checks["categories"]:
        print(f"    {cat['name']:50s} {cat['count']:>3d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
