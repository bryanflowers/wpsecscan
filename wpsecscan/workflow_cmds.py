"""v2.7.0 PhaseC — workflow / orchestration subcommand handlers.

Houses the implementation of D61-D71 (minus already-shipped D67 = kev).
Each handler is a self-contained _cmd_X(args: list[str]) function the
main dispatcher imports.
"""
from __future__ import annotations

import json
import sys
import tarfile
import time
from pathlib import Path

from ._util import home_dir, load_home_json


# ---------------------------------------------------------------------------
# D61 — wpsecscan compare-portfolios
# ---------------------------------------------------------------------------

def cmd_compare_portfolios(args: list[str]) -> None:
    """`wpsecscan compare-portfolios OLD.json NEW.json [--out FILE]`

    Diff two `sites.json` files side-by-side. Each file is a list of
    site objects (target + tags + creds-key). Reports sites added,
    sites removed, and tag-only changes — useful for agency M&A
    due-diligence.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("usage: wpsecscan compare-portfolios OLD.json NEW.json [--out FILE]",
              file=sys.stderr)
        sys.exit(64)
    old_path = Path(args[0]).expanduser()
    new_path = Path(args[1]).expanduser()
    try:
        old = json.loads(old_path.read_text(encoding="utf-8"))
        new = json.loads(new_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"failed to parse input files: {e}", file=sys.stderr); sys.exit(2)
    if not isinstance(old, list) or not isinstance(new, list):
        print("expected each file to be a top-level JSON array", file=sys.stderr); sys.exit(64)

    old_by = {s.get("target"): s for s in old if isinstance(s, dict)}
    new_by = {s.get("target"): s for s in new if isinstance(s, dict)}
    added   = sorted(set(new_by) - set(old_by))
    removed = sorted(set(old_by) - set(new_by))
    common  = set(new_by) & set(old_by)
    tag_changes = []
    for t in sorted(common):
        a = set(old_by[t].get("tags") or [])
        b = set(new_by[t].get("tags") or [])
        if a != b:
            tag_changes.append({"target": t,
                                  "added_tags": sorted(b - a),
                                  "removed_tags": sorted(a - b)})

    print(f"Sites added:    {len(added)}")
    for t in added: print(f"  + {t}")
    print(f"Sites removed:  {len(removed)}")
    for t in removed: print(f"  - {t}")
    print(f"Tag changes:    {len(tag_changes)}")
    for c in tag_changes:
        print(f"  ~ {c['target']} +{c['added_tags']} -{c['removed_tags']}")


# ---------------------------------------------------------------------------
# D63 — wpsecscan changelog URL --since DATE
# ---------------------------------------------------------------------------

def cmd_changelog(args: list[str]) -> None:
    """`wpsecscan changelog URL [--since YYYY-MM-DD]`

    Render a human-readable changelog of observed changes across saved
    snapshots — plugin versions, theme switches, header changes, cert
    renewals. Different from the existing diff-tree (which compares
    findings only).
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan changelog URL [--since YYYY-MM-DD]", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    since = ""
    for i, a in enumerate(args[1:]):
        if a == "--since" and i + 2 <= len(args[1:]):
            since = args[i + 2]
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved snapshots for {url}", file=sys.stderr); sys.exit(2)

    rows: list[dict] = []
    prev_plugins: dict[str, str] = {}
    prev_theme: str = ""
    for snap in snaps:
        try:
            d = json.loads(snap.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ts = d.get("scanned_at", snap.name)
        if since and ts < since:
            continue
        cur_plugins: dict[str, str] = {}
        cur_theme: str = ""
        for r in d.get("results", []):
            cid = r.get("check_id", "")
            for f in r.get("findings", []):
                extra = f.get("extra") or {}
                if cid == "plugins" and extra.get("slug") and extra.get("version"):
                    cur_plugins[extra["slug"]] = str(extra["version"])
                if cid == "themes" and extra.get("active_theme"):
                    cur_theme = str(extra["active_theme"])
        # Plugin diff vs previous
        for slug, ver in cur_plugins.items():
            if slug not in prev_plugins:
                rows.append({"ts": ts, "kind": "plugin-added",
                              "subject": f"{slug} @ {ver}"})
            elif prev_plugins[slug] != ver:
                rows.append({"ts": ts, "kind": "plugin-upgrade",
                              "subject": f"{slug}: {prev_plugins[slug]} → {ver}"})
        for slug in set(prev_plugins) - set(cur_plugins):
            rows.append({"ts": ts, "kind": "plugin-removed", "subject": slug})
        if cur_theme and cur_theme != prev_theme and prev_theme:
            rows.append({"ts": ts, "kind": "theme-switch",
                          "subject": f"{prev_theme} → {cur_theme}"})
        prev_plugins, prev_theme = cur_plugins, cur_theme

    if not rows:
        print(f"No observed changes for {url}" + (f" since {since}" if since else "."))
        return
    print(f"# WPSecScan-observed changelog: {url}")
    if since:
        print(f"# Since: {since}")
    print()
    for r in rows:
        print(f"  {r['ts']}  {r['kind']:18s}  {r['subject']}")


# ---------------------------------------------------------------------------
# D64 — wpsecscan replay HAR.json
# ---------------------------------------------------------------------------

def cmd_replay(args: list[str]) -> None:
    """`wpsecscan replay HAR.json [--list | --show INDEX]`

    Air-gapped audit helper. Reads an HTTP Archive (HAR) file and lets
    the operator browse the recorded requests + responses. Future
    extension: feed HAR entries to specific checks instead of live HTTP.
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan replay HAR.json [--list | --show INDEX]",
              file=sys.stderr)
        sys.exit(64)
    p = Path(args[0]).expanduser()
    if not p.exists():
        print(f"file not found: {p}", file=sys.stderr); sys.exit(2)
    try:
        har = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"failed to parse HAR: {e}", file=sys.stderr); sys.exit(2)
    entries = (har.get("log") or {}).get("entries") or []
    if not entries:
        print("HAR contains no entries.", file=sys.stderr); sys.exit(0)
    mode = "list"
    show_idx: int | None = None
    for i, a in enumerate(args[1:]):
        if a == "--list":
            mode = "list"
        elif a == "--show" and i + 2 <= len(args[1:]):
            try:
                show_idx = int(args[i + 2])
            except ValueError:
                pass
    if mode == "list" and show_idx is None:
        print(f"HAR: {len(entries)} entries from {p.name}")
        for i, e in enumerate(entries):
            req = e.get("request") or {}
            resp = e.get("response") or {}
            print(f"  [{i:3d}] {req.get('method', '?'):5s} "
                   f"{resp.get('status', 0):3d}  {req.get('url', '?')[:90]}")
    elif show_idx is not None and 0 <= show_idx < len(entries):
        import pprint
        pprint.pp(entries[show_idx])
    else:
        print(f"index {show_idx} out of range (0-{len(entries) - 1})",
              file=sys.stderr); sys.exit(64)


# ---------------------------------------------------------------------------
# D65 — wpsecscan freeze URL
# ---------------------------------------------------------------------------

def cmd_freeze(args: list[str]) -> None:
    """`wpsecscan freeze URL [--out FILE]`

    Snapshot a site for offline comparison: bundles the most-recent
    saved JSON snapshot + any HTML reports + the OpenAPI schema into a
    .tar.gz the operator can archive for offline re-comparison years
    later. Extension of #79 reference-diff (which compares LIVE state
    vs a known-clean WP zip; this freezes the LIVE state itself).
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan freeze URL [--out FILE]", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    out_path: Path | None = None
    for i, a in enumerate(args[1:]):
        if a == "--out" and i + 2 <= len(args[1:]):
            out_path = Path(args[i + 2]).expanduser()
    from . import history as _h
    from urllib.parse import urlparse
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved snapshots for {url}", file=sys.stderr); sys.exit(2)
    if out_path is None:
        safe = (urlparse(url).hostname or "site").replace(":", "_")
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out_path = Path.cwd() / f"wpsecscan-freeze-{safe}-{ts}.tar.gz"

    # B2 (v2.7.1) — strip any directory separators from snapshot filenames
    # before they become tarball arcnames. Defence-in-depth so a recipient
    # extracting the .tar.gz can't be tricked into writing outside the
    # extraction root by a hostile snapshot filename.
    with tarfile.open(out_path, "w:gz") as tf:
        latest = snaps[-1]
        tf.add(str(latest), arcname=f"snapshots/{Path(latest.name).name}")
        for snap in snaps:
            tf.add(str(snap), arcname=f"history/{Path(snap.name).name}")
        try:
            sch = Path(__file__).parent / "data" / "openapi-scan-report.json"
            if sch.exists():
                tf.add(str(sch), arcname="schema/openapi-scan-report.json")
        except OSError:
            pass
    print(f"frozen {len(snaps)} snapshot(s) → {out_path}")


# ---------------------------------------------------------------------------
# D66 — wpsecscan attest URL --keyless
# ---------------------------------------------------------------------------

def cmd_attest(args: list[str]) -> None:
    """`wpsecscan attest URL --keyless`

    Generate a Sigstore-signed attestation of the most-recent scan
    that the site owner can publish (e.g. at /.well-known/security-
    attestation.json) to prove their posture at a point in time.

    Without --keyless, emits the unsigned attestation payload + the
    `cosign sign-blob` command the operator can run with their own
    Sigstore identity.
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan attest URL [--keyless] [--out FILE]",
              file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    keyless = "--keyless" in args[1:]
    out_path: Path | None = None
    for i, a in enumerate(args[1:]):
        if a == "--out" and i + 2 <= len(args[1:]):
            out_path = Path(args[i + 2]).expanduser()

    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan for {url}", file=sys.stderr); sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    from . import __version__
    payload = {
        "subject": url,
        "predicateType": "https://wpsecscan.dev/attest/v1",
        "predicate": {
            "scanner": "wpsecscan",
            "scanner_version": __version__,
            "scanned_at": data.get("scanned_at", ""),
            "risk_score": data.get("risk_score", 0),
            "summary": data.get("summary", {}),
            "snapshot_sha256": _h.snapshot_signature(snaps[-1])
                if hasattr(_h, "snapshot_signature") else "",
        },
        "_format": "in-toto attestation v1",
    }
    if out_path is None:
        out_path = Path.cwd() / f"wpsecscan-attest-{int(time.time())}.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"attestation payload written: {out_path}")
    if keyless:
        print("# Sign with Sigstore (requires `cosign` on PATH + GitHub login):")
        print(f"  cosign sign-blob --yes {out_path} \\")
        print(f"    --output-signature {out_path}.sig \\")
        print(f"    --output-certificate {out_path}.pem")
    else:
        print("# Pass --keyless to print the cosign signing command.")


# ---------------------------------------------------------------------------
# D68 — wpsecscan compliance audit URL --framework soc2
# ---------------------------------------------------------------------------

def cmd_compliance_audit(args: list[str]) -> None:
    """`wpsecscan compliance audit URL --framework {soc2,iso,pci,nist,hitrust,cmmc,cis,csf}`

    Single-framework gap analysis: lists the framework controls covered
    by SOME wpsecscan check + which of THOSE checks fired on the latest
    scan. Different from the existing 8-framework attestation matrix
    (which shows ALL controls regardless of whether they're exercised).
    """
    if not args or args[0] in ("-h", "--help") or args[0] != "audit":
        print("usage: wpsecscan compliance audit URL --framework FRAMEWORK",
              file=sys.stderr)
        sys.exit(64)
    rest = args[1:]
    if not rest:
        print("missing URL", file=sys.stderr); sys.exit(64)
    url = rest[0]
    if "://" not in url:
        url = "https://" + url
    framework = "soc2"
    for i, a in enumerate(rest[1:]):
        if a == "--framework" and i + 2 <= len(rest[1:]):
            framework = rest[i + 2].lower()
    framework_keys = {
        "soc2":      ["nist_800_53", "iso_27001"],
        "iso":       ["iso_27001"],
        "pci":       ["pci_dss"],
        "nist":      ["nist_800_53"],
        "hitrust":   ["hitrust"],
        "cmmc":      ["cmmc"],
        "cis":       ["cis_v8"],
        "csf":       ["nist_csf"],
    }
    keys = framework_keys.get(framework)
    if not keys:
        print(f"unknown framework {framework!r}; pick: {', '.join(framework_keys)}",
              file=sys.stderr)
        sys.exit(64)

    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan for {url} — run a scan first", file=sys.stderr); sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    check_ids_with_findings = {r.get("check_id") for r in data.get("results", []) if r.get("findings")}
    # Load both compliance JSONs
    base = Path(__file__).parent / "data"
    cm1 = json.loads((base / "compliance_map.json").read_text(encoding="utf-8"))
    cm2 = json.loads((base / "compliance_v2.json").read_text(encoding="utf-8"))
    merged: dict[str, dict] = {}
    for src in (cm1, cm2):
        for cid, ctrls in src.items():
            if cid.startswith("_"):
                continue
            if cid not in merged:
                merged[cid] = {}
            if isinstance(ctrls, dict):
                merged[cid].update(ctrls)

    print(f"# Compliance audit — {framework.upper()}")
    print(f"# Target: {url}")
    print(f"# Snapshot: {snaps[-1].name}")
    print()
    print(f"{'CHECK':30s}  {'STATUS':12s}  {'CONTROLS':50s}")
    print(f"{'-' * 30}  {'-' * 12}  {'-' * 50}")
    for cid in sorted(merged):
        ctrls = []
        for k in keys:
            v = merged[cid].get(k)
            if v:
                ctrls.append(f"{k}={v}")
        if not ctrls:
            continue
        status = "FIRED" if cid in check_ids_with_findings else "clean"
        print(f"{cid:30s}  {status:12s}  {', '.join(ctrls)}")


# ---------------------------------------------------------------------------
# D62 — wpsecscan tournament
# ---------------------------------------------------------------------------

def cmd_tournament(args: list[str]) -> None:
    """`wpsecscan tournament URL CONFIG_A.yml CONFIG_B.yml`

    Bake-off helper: runs the SAME URL under two different --config
    files and reports per-finding precision/recall vs the union of
    findings. Helps the operator decide which check-set is worth the
    extra scan time.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 3:
        print("usage: wpsecscan tournament URL CONFIG_A.yml CONFIG_B.yml",
              file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    cfg_a = Path(args[1]).expanduser()
    cfg_b = Path(args[2]).expanduser()
    for p in (cfg_a, cfg_b):
        if not p.exists():
            print(f"config file not found: {p}", file=sys.stderr); sys.exit(2)
    import subprocess
    results: dict[str, set[tuple[str, str]]] = {}
    for label, cfg in (("A", cfg_a), ("B", cfg_b)):
        print(f"[tournament] running {label}: --config {cfg}", file=sys.stderr)
        try:
            subprocess.run(
                [sys.executable, "-m", "wpsecscan", url, "--json-only", "--no-console",
                  "--no-update-check", "--config", str(cfg)],
                capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            print(f"  config {label} timed out")
            continue
        from . import history as _h
        snaps = _h.snapshot_history(url)
        if not snaps:
            results[label] = set()
            continue
        data = json.loads(snaps[-1].read_text(encoding="utf-8"))
        s: set[tuple[str, str]] = set()
        for r in data.get("results", []):
            for f in r.get("findings", []):
                s.add((r["check_id"], f.get("title", "")))
        results[label] = s
    a, b = results.get("A", set()), results.get("B", set())
    union = a | b
    print(f"Tournament: {url}")
    print(f"  Union of findings: {len(union)}")
    print(f"  Config A: {len(a)} ({100*len(a)/max(1, len(union)):.0f}% recall)")
    print(f"  Config B: {len(b)} ({100*len(b)/max(1, len(union)):.0f}% recall)")
    print(f"  A-only:   {len(a - b)}")
    print(f"  B-only:   {len(b - a)}")
    print(f"  Both:     {len(a & b)}")


# ---------------------------------------------------------------------------
# D69 — wpsecscan ai-agent URL
# ---------------------------------------------------------------------------

def cmd_ai_agent(args: list[str]) -> None:
    """`wpsecscan ai-agent URL`

    Runs a passive scan, then asks the AI "given these findings, what
    would you probe next?" and prints recommended follow-up scan
    invocations. NOT auto-executing — the operator chooses which to run.
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan ai-agent URL", file=sys.stderr); sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    from . import history as _h, ai_assist as _ai
    snaps = _h.snapshot_history(url)
    if not snaps:
        print("run a passive scan first: wpsecscan " + url, file=sys.stderr)
        sys.exit(2)
    if not _ai.is_configured():
        print("ai-agent requires WPSECSCAN_OPENAI_API_KEY / ANTHROPIC / OLLAMA",
              file=sys.stderr)
        sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    lines = []
    for r in data.get("results", []):
        for f in r.get("findings", []):
            if f.get("severity") in ("high", "critical"):
                lines.append(f"{f['severity']}|{r['check_id']}|{f.get('title','')[:120]}")
    prompt = (
        f"You are a senior WordPress security auditor. The first-pass scan of\n"
        f"  {url}\n"
        f"surfaced these high/critical findings (severity|check_id|title):\n\n"
        + "\n".join(lines[:60]) + "\n\n"
        "Recommend 3-5 follow-up commands the operator should run NEXT to "
        "verify or expand each finding. Output one line per recommendation in "
        "the format:\n"
        "  RANK | wpsecscan-command | one-line reason\n"
        "No commentary."
    )
    resp = _ai.llm(prompt, max_tokens=600) if hasattr(_ai, "llm") else ""
    if not resp:
        print("AI returned no recommendations.")
        return
    print(f"# ai-agent recommendations for {url}")
    print()
    print(resp)


# ---------------------------------------------------------------------------
# D70 — wpsecscan triage interactive
# ---------------------------------------------------------------------------

def cmd_triage(args: list[str]) -> None:
    """`wpsecscan triage interactive URL`

    Walks through each finding from the most-recent scan asking the
    operator: keep / snooze / raise-severity / push-to-jira / skip.
    Writes the operator's choices into ~/.wpsecscan/policy.yml
    (severity_overrides + suppress entries).
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2 or args[0] != "interactive":
        print("usage: wpsecscan triage interactive URL", file=sys.stderr)
        sys.exit(64)
    url = args[1]
    if "://" not in url:
        url = "https://" + url
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan for {url}", file=sys.stderr); sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    policy_path = home_dir() / "policy.yml"
    decisions: list[dict] = []
    for r in data.get("results", []):
        for f in r.get("findings", []):
            if f.get("severity") == "info":
                continue
            print()
            print(f"[{f['severity']:8s}] {r['check_id']}: {f.get('title','')}")
            print(f"           {(f.get('evidence') or '')[:200]}")
            try:
                ans = input("[k]eep / [s]nooze / [r]aise / [p]ush / e[x]it: ").strip().lower()
            except EOFError:
                break
            if ans == "x":
                break
            if ans == "s":
                decisions.append({"action": "snooze", "check_id": r["check_id"],
                                    "title": f.get("title", "")})
            elif ans == "r":
                decisions.append({"action": "raise",  "check_id": r["check_id"],
                                    "title": f.get("title", "")})
            elif ans == "p":
                decisions.append({"action": "push",   "check_id": r["check_id"],
                                    "title": f.get("title", "")})
    if not decisions:
        print("\nNo changes recorded.")
        return
    # Append to policy.yml as plain comments + serialised YAML
    snippet = ["", "# triage interactive session @ " + time.strftime("%Y-%m-%dT%H:%M:%S")]
    for d in decisions:
        snippet.append(f"# {d['action']}: {d['check_id']} / {d['title'][:80]}")
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    with policy_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(snippet) + "\n")
    print(f"\nWrote {len(decisions)} decision(s) to {policy_path}")
    print("(merge manually into severity_overrides / suppress sections)")


# ---------------------------------------------------------------------------
# D71 — wpsecscan cron-schedule add-rotation
# ---------------------------------------------------------------------------

def cmd_rotation(args: list[str]) -> None:
    """`wpsecscan rotation N URL_LIST_FILE [--flags ...]`

    Split URL_LIST_FILE into N daily buckets and add cron-schedule
    entries to scan one bucket per day-of-week. A 90-site operator with
    N=3 scans 30 sites/day on Mon/Tue/Wed, finishing the portfolio
    every Wed without WAF rate-limit issues.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("usage: wpsecscan rotation N URL_LIST.txt [-- extra flags]",
              file=sys.stderr); sys.exit(64)
    try:
        n_buckets = int(args[0])
    except ValueError:
        print("first arg must be integer N (1-7)", file=sys.stderr); sys.exit(64)
    if not 1 <= n_buckets <= 7:
        print("N must be 1-7 (days of week)", file=sys.stderr); sys.exit(64)
    list_path = Path(args[1]).expanduser()
    if not list_path.exists():
        print(f"URL list not found: {list_path}", file=sys.stderr); sys.exit(2)
    extra: list[str] = []
    if "--" in args[2:]:
        extra = args[args.index("--", 2) + 1:]
    urls = [u.strip() for u in list_path.read_text(encoding="utf-8").splitlines()
             if u.strip() and not u.startswith("#")]
    if not urls:
        print("URL list is empty", file=sys.stderr); sys.exit(2)
    from . import scheduler as _sch
    bucket_size = (len(urls) + n_buckets - 1) // n_buckets
    n_added = 0
    for i in range(n_buckets):
        chunk = urls[i * bucket_size:(i + 1) * bucket_size]
        for url in chunk:
            cron_expr = f"0 3 * * {i}"  # day-of-week = bucket index
            _sch.add(cron_expr, url, extra, name=f"rotation-bucket{i}-{url[:30]}")
            n_added += 1
    print(f"added {n_added} cron entries across {n_buckets} daily buckets")
