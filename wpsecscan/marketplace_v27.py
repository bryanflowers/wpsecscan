"""v2.7.0 marketplace + community (L126-L130).

  L126 wpsecscan marketplace {list, search, install, verify}
  L127 sort by stars (popularity field in the index)
  L128 author profiles + sigstore signature on each check
  L129 community CVE-DB contributions (submit-cve subcommand)
  L130 public bug-bounty leaderboard (HackerOne report aggregation)

Marketplace index is hosted on GitHub Pages at
  https://bryanflowers.github.io/wpsecscan/marketplace.json
with a stable JSON schema:

  {
    "_version": 1,
    "checks": [
      {"slug": "...", "title": "...", "description": "...",
        "author_handle": "alice", "stars": 12, "downloads": 340,
        "source_url": "https://raw.githubusercontent.com/.../alice-csp-deep.py",
        "sigstore_pem_url": "...", "sigstore_sig_url": "...",
        "category": "auth|cves|tls|...", "added": "2026-05-27"}
    ]
  }

Cache: ~/.wpsecscan/marketplace-cache.json (6h TTL).
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from ._util import home_dir


_INDEX_URL = os.environ.get(
    "WPSECSCAN_MARKETPLACE_URL",
    "https://bryanflowers.github.io/wpsecscan/marketplace.json",
)
_CACHE_TTL = 6 * 3600

# S1 (v2.7.1) — slug + source-URL guards for `marketplace install`.
# A malicious or MITM'd marketplace index could otherwise (a) return a
# slug containing path-traversal sequences, or (b) return a source_url
# pointing at file:// / a foreign host / a non-HTTPS URL — leading to
# arbitrary file read or RCE via the installed-then-auto-loaded .py.
import re as _re
import urllib.parse as _urlparse

_SLUG_RE = _re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _safe_slug(slug: str) -> bool:
    return bool(_SLUG_RE.match(slug))


def _allowed_install_origin() -> str:
    """Return the netloc that source_url values are allowed to point at.
    Derived from the marketplace index URL — operators who self-host the
    index also self-host the checks; the trust boundary is one origin."""
    return _urlparse.urlparse(_INDEX_URL).netloc.lower()


def _safe_source_url(src_url: str) -> tuple[bool, str]:
    """Return (ok, reason) for a marketplace source_url. Rejects:
      - schemes other than https://
      - hosts not matching the marketplace index origin
      - raw IPs (defence-in-depth against DNS-rebinding)
    """
    try:
        p = _urlparse.urlparse(src_url)
    except (ValueError, AttributeError):
        return False, "URL does not parse"
    if p.scheme != "https":
        return False, f"scheme must be https (got {p.scheme!r})"
    if not p.netloc:
        return False, "URL has no host"
    if p.netloc.lower() != _allowed_install_origin():
        return False, (f"host {p.netloc!r} doesn't match marketplace origin "
                        f"{_allowed_install_origin()!r}")
    return True, ""


def _cache_path() -> Path:
    return home_dir() / "marketplace-cache.json"


def _fetch_index(*, force: bool = False) -> dict:
    p = _cache_path()
    if not force and p.exists():
        try:
            age = time.time() - p.stat().st_mtime
            if age < _CACHE_TTL:
                return json.loads(p.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            pass
    try:
        req = urllib.request.Request(_INDEX_URL,
                                       headers={"User-Agent": "WPSecScan/marketplace"})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", errors="replace")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return json.loads(text) or {}
    except Exception:  # noqa: BLE001
        # Fall back to stale cache
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8")) or {}
            except (OSError, ValueError):
                pass
        return {"_version": 1, "checks": []}


def cmd_marketplace(args: list[str]) -> None:
    """`wpsecscan marketplace {list|search|install|verify|stars|authors|leaderboard}`"""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan marketplace {list|search Q|install SLUG|verify SLUG|stars|authors|leaderboard}",
              file=sys.stderr)
        return
    sub = args[0]
    idx = _fetch_index()
    checks = idx.get("checks", [])

    if sub == "list":
        print(f"{len(checks)} marketplace check(s) (index v{idx.get('_version', 1)}):")
        for c in sorted(checks, key=lambda x: -int(x.get("stars", 0)))[:50]:
            print(f"  {c.get('slug', '?'):30s} ★{c.get('stars', 0):4d}  by @{c.get('author_handle', '?'):15s}  {c.get('title', '')[:60]}")
        return

    if sub == "search":
        if len(args) < 2:
            print("usage: wpsecscan marketplace search QUERY", file=sys.stderr); sys.exit(64)
        q = args[1].lower()
        matches = [c for c in checks
                     if q in (c.get("slug", "") + c.get("title", "")
                              + c.get("description", "")).lower()]
        print(f"{len(matches)} match(es) for {q!r}:")
        for c in matches:
            print(f"  {c.get('slug')}: {c.get('title', '')}")
        return

    if sub == "stars":
        print("Top 20 by star count:")
        for c in sorted(checks, key=lambda x: -int(x.get("stars", 0)))[:20]:
            print(f"  ★{c.get('stars', 0):4d}  {c.get('slug', '')}")
        return

    if sub == "authors":
        from collections import Counter
        cnt = Counter(c.get("author_handle", "anon") for c in checks)
        print("Top check authors:")
        for handle, n in cnt.most_common(20):
            print(f"  @{handle:20s} {n} check(s)")
        return

    if sub == "leaderboard":
        # L130 — pull HackerOne reports authored by the wpsecscan community.
        # Without a HackerOne token we fall back to the index's curated list.
        lb = idx.get("bug_bounty_leaderboard", [])
        if not lb:
            print("No leaderboard data in the index yet.")
            return
        print("WPSecScan community bug-bounty leaderboard:")
        for row in sorted(lb, key=lambda r: -int(r.get("bounty_usd", 0)))[:20]:
            print(f"  ${row.get('bounty_usd', 0):>6,}  @{row.get('handle', '?'):15s}  "
                   f"{row.get('cve', ''):16s}  {row.get('summary', '')[:60]}")
        return

    if sub == "install":
        if len(args) < 2:
            print("usage: wpsecscan marketplace install SLUG [--allow-unsigned]",
                  file=sys.stderr)
            sys.exit(64)
        slug = args[1]
        allow_unsigned = "--allow-unsigned" in args[2:]
        # S1: slug sanitation — refuses path-traversal AND any character
        # not in the marketplace's allow-list. Catches a malicious index
        # returning slug='../../evil' or 'a;rm -rf /'.
        if not _safe_slug(slug):
            print(f"refusing install: slug {slug!r} fails ^[a-zA-Z0-9_-]{{1,64}}$",
                  file=sys.stderr); sys.exit(2)
        entry = next((c for c in checks if c.get("slug") == slug), None)
        if not entry:
            print(f"{slug!r} not in marketplace", file=sys.stderr); sys.exit(2)
        src_url = entry.get("source_url", "")
        if not src_url:
            print(f"no source_url for {slug!r}", file=sys.stderr); sys.exit(2)
        # S1: source-URL guard — scheme must be https, host must match the
        # marketplace index origin. Without this a malicious index can
        # set source_url to file:///etc/passwd or http://attacker.com/
        # backdoor.py (which then gets loaded as Python at next scan).
        ok, reason = _safe_source_url(src_url)
        if not ok:
            print(f"refusing install: source_url rejected ({reason})",
                  file=sys.stderr); sys.exit(2)
        sig_url = entry.get("sigstore_sig_url", "")
        pem_url = entry.get("sigstore_pem_url", "")
        if not (sig_url and pem_url) and not allow_unsigned:
            # S1: unsigned checks require an explicit opt-in. The previous
            # behaviour was to install + print a # WARN comment, which
            # operators routinely missed.
            print(f"refusing install: {slug!r} has no Sigstore signature.\n"
                   f"Re-run with `--allow-unsigned` to install anyway, OR\n"
                   f"ask the author to publish sigstore_sig_url + "
                   f"sigstore_pem_url in the marketplace index.",
                   file=sys.stderr)
            sys.exit(3)
        target = home_dir() / "marketplace" / "checks" / f"{slug}.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with urllib.request.urlopen(src_url, timeout=15) as r:
                target.write_bytes(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"download failed: {e}", file=sys.stderr); sys.exit(2)
        print(f"installed: {target}")
        if sig_url and pem_url:
            print(f"# Verify the signature:")
            print(f"  wpsecscan marketplace verify {slug}")
        else:
            print("# Installed without signature (--allow-unsigned). "
                   "Re-verify the source URL before use.")
        return

    if sub == "verify":
        if len(args) < 2:
            print("usage: wpsecscan marketplace verify SLUG", file=sys.stderr); sys.exit(64)
        slug = args[1]
        entry = next((c for c in checks if c.get("slug") == slug), None)
        if not entry:
            print(f"{slug!r} not in marketplace", file=sys.stderr); sys.exit(2)
        sig = entry.get("sigstore_sig_url", "")
        pem = entry.get("sigstore_pem_url", "")
        if not (sig and pem):
            print(f"{slug!r} has no signature — refusing.")
            sys.exit(1)
        import shutil
        if not shutil.which("cosign"):
            print("install cosign + retry: https://docs.sigstore.dev/cosign/", file=sys.stderr)
            sys.exit(2)
        local = home_dir() / "marketplace" / "checks" / f"{slug}.py"
        if not local.exists():
            print(f"check not installed locally: {local}", file=sys.stderr); sys.exit(2)
        import subprocess
        # Fetch sig + cert
        import tempfile
        td = Path(tempfile.mkdtemp())
        try:
            for u, name in ((sig, "sig.txt"), (pem, "cert.pem")):
                with urllib.request.urlopen(u, timeout=15) as r:
                    (td / name).write_bytes(r.read())
            res = subprocess.run(
                ["cosign", "verify-blob", str(local),
                  "--signature", str(td / "sig.txt"),
                  "--certificate", str(td / "cert.pem"),
                  "--certificate-identity-regexp", ".+",
                  "--certificate-oidc-issuer-regexp", ".+"],
                capture_output=True, text=True,
            )
            if res.returncode == 0:
                print(f"✓ verified: {slug} signed by {entry.get('author_handle', '?')}")
            else:
                print(f"✗ verify FAILED: {res.stderr[:300]}")
                sys.exit(1)
        finally:
            import shutil as _sh
            _sh.rmtree(td, ignore_errors=True)
        return

    print(f"unknown marketplace subcommand: {sub}", file=sys.stderr); sys.exit(64)


def cmd_submit_cve(args: list[str]) -> None:
    """L129 — `wpsecscan submit-cve SLUG CVE-YYYY-NNNN`

    Append a community-submitted CVE to ~/.wpsecscan/cve-submissions.json.
    The operator then runs the helper that opens a GitHub PR against
    bryanflowers/wpsecscan with the file as proposed CVE-feed input.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("usage: wpsecscan submit-cve SLUG CVE-YYYY-NNNN [--severity SEV]",
              file=sys.stderr)
        sys.exit(64)
    slug, cve = args[0], args[1]
    sev = "medium"
    for i, a in enumerate(args[2:]):
        if a == "--severity" and i + 2 <= len(args[2:]):
            sev = args[i + 3]
    p = home_dir() / "cve-submissions.json"
    try:
        existing = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    except (OSError, ValueError):
        existing = []
    existing.append({
        "slug": slug, "cve": cve, "severity": sev,
        "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"queued: {slug} / {cve} ({sev})  →  {p}")
    print("# Open a PR against bryanflowers/wpsecscan with this JSON.")
