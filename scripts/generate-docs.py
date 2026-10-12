"""Auto-generate per-check markdown docs from the check modules.

Usage:
    python scripts/generate-docs.py [--out DIR] [--site-checks checks.json]

Writes one .md per registered check into ./docs/checks/<check_id>.md plus an
index at docs/checks/README.md, and deletes pages for ids that are no longer
in the registry. Idempotent: safe to re-run.

Everything on a page comes from the repository: the module docstring, the
literal ``Finding(...)`` calls found with ``ast`` (check modules are parsed,
never imported here; only the registry in ``wpsecscan.checks`` is), the
``wpsecscan/data`` tag / compliance / reference / quick-fix files, and the
``https://`` literals in the module. Every page opens with YAML front matter
(id, title, severity_max, aggressive, category, words) so the website can
build ``/docs/checks/<id>/`` from it.

Categories are copied from the website's ``src/data/checks.json`` (pass
``--site-checks`` or set WPSECSCAN_SITE_CHECKS_JSON). Without that file the
keyword heuristic of scripts/export-site-data.py is used.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import inspect
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wpsecscan.checks import ALL_CHECKS  # noqa: E402

DATA_DIR = ROOT / "wpsecscan" / "data"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
REQUEST_METHODS = ("get", "head", "post", "put", "delete", "patch", "options", "request")
EXAMPLE_TARGET = "https://example.com"
# The site's checks.json has no row for the credentialed-scan driver.
FALLBACK_CATEGORY = "Authenticated"

_URL_RE = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&*+,;=%\-\[\]]+")
_SKIP_URL_HOSTS = ("example.com", "example.org", "localhost", "evil", "attacker", "127.0.0.1")


# ---------------------------------------------------------------------------
# data files
# ---------------------------------------------------------------------------
def _load_json(name: str) -> dict:
    try:
        return json.loads((DATA_DIR / name).read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _tags_for(check_id: str) -> dict:
    return _load_json("check_tags.json").get(check_id, {})


def _compliance_for(check_id: str) -> dict:
    out: dict[str, dict] = {}
    for fname in ("compliance_map.json", "compliance_extra.json", "compliance_v2.json"):
        d = _load_json(fname)
        if isinstance(d.get(check_id), dict):
            out[fname.replace(".json", "")] = d[check_id]
    return out


# ---------------------------------------------------------------------------
# categories
# ---------------------------------------------------------------------------
def _load_categories(site_checks: Path | None) -> tuple[dict[str, str], list[str]]:
    """Return ({check_id: category}, category display order)."""
    mapping: dict[str, str] = {}
    order: list[str] = []
    if site_checks and site_checks.is_file():
        try:
            data = json.loads(site_checks.read_text(encoding="utf-8"))
            for cat in data.get("categories", []):
                order.append(cat["name"])
                for ck in cat.get("checks", []):
                    if ck.get("id"):
                        mapping[ck["id"]] = cat["name"]
        except (OSError, ValueError, KeyError, AttributeError, TypeError):
            mapping, order = {}, []
    return mapping, order


def _heuristic_category(cid: str, name: str) -> str:
    """Fallback: reuse the keyword table of scripts/export-site-data.py."""
    try:
        spec = importlib.util.spec_from_file_location(
            "_export_site_data", ROOT / "scripts" / "export-site-data.py")
        if spec is None or spec.loader is None:
            return "Other"
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._category_for(cid, name, {})
    except Exception:  # noqa: BLE001
        return "Other"


# ---------------------------------------------------------------------------
# static extraction
# ---------------------------------------------------------------------------
def _placeholder(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return f"⟨{node.id}⟩"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len":
        return "⟨count⟩"
    return "⟨value⟩"


def _render_str(node: ast.AST | None) -> str | None:
    """Render a literal / f-string / 'a' + 'b' as text; ⟨x⟩ marks unknown parts."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                parts.append(_placeholder(v.value))
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _render_str(node.left), _render_str(node.right)
        if left is None:
            left = _placeholder(node.left)
        if right is None:
            right = _placeholder(node.right)
        return left + right
    if isinstance(node, ast.IfExp):
        a, b = _render_str(node.body), _render_str(node.orelse)
        if a is not None and b is not None:
            if a == b or not b.strip():
                return a
            return b if not a.strip() else f"{a} / {b}"
    return None


def _is_severity(value: object) -> bool:
    return isinstance(value, str) and value in _SEV_RANK


def _module_collection_severities(tree: ast.Module) -> set[str]:
    """Severity words held in module-level dict/list/tuple constants."""
    found: set[str] = set()
    for node in tree.body:
        value = None
        if isinstance(node, ast.Assign):
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            value = node.value
        if isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            for sub in ast.walk(value):
                if isinstance(sub, ast.Constant) and _is_severity(sub.value):
                    found.add(sub.value)
    return found


def _data_file_severities(tree: ast.Module) -> set[str]:
    """Severity words in `path|severity|label` data files the module names (known_paths.txt)."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(".txt"):
            f = DATA_DIR / node.value
            if f.is_file():
                try:
                    lines = f.read_text(encoding="utf-8").splitlines()
                except OSError:
                    continue
                for line in lines:
                    parts = line.split("|")
                    if len(parts) == 3 and _is_severity(parts[1].strip()):
                        found.add(parts[1].strip())
    return found


def _name_assignments(tree: ast.Module, name: str) -> list[ast.AST]:
    out: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    out.append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name and node.value:
                out.append(node.value)
    return out


def _severity_candidates(node: ast.AST | None, tree: ast.Module, coll: set[str]) -> tuple[set[str], bool]:
    """(possible severities, fully_resolved) for a Finding(severity=...) expr."""
    if node is None:
        return set(), False
    if isinstance(node, ast.Constant):
        return ({node.value} if _is_severity(node.value) else set()), _is_severity(node.value)
    if isinstance(node, ast.IfExp):
        a, ra = _severity_candidates(node.body, tree, coll)
        b, rb = _severity_candidates(node.orelse, tree, coll)
        return a | b, ra and rb
    if isinstance(node, ast.Name):
        assigned = _name_assignments(tree, node.id)
        if assigned:
            cands: set[str] = set()
            ok = True
            for value in assigned:
                c, r = _severity_candidates(value, tree, coll)
                cands |= c
                ok = ok and r
            if cands:
                return cands, ok
    # Subscript / Attribute / Call / loop variable: fall back to the severity
    # words held in module-level tables (dict of header -> (severity, fix)).
    return set(coll), False


def _request_sites(tree: ast.Module) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in REQUEST_METHODS):
            base = node.func.value
            if isinstance(base, ast.Name) and base.id in ("client", "c", "cl"):
                counts[node.func.attr] = counts.get(node.func.attr, 0) + 1
    return counts


def _urls_in(tree: ast.Module) -> list[str]:
    seen: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "https://" in node.value:
            for m in _URL_RE.findall(node.value):
                url = m.rstrip(".,;:)]")
                host = url.split("/")[2] if url.count("/") >= 2 else url
                if any(s in host for s in _SKIP_URL_HOSTS) or len(url) <= len("https://x.y"):
                    continue
                if url not in seen:
                    seen.append(url)
    return seen


def _analyse(path: Path) -> dict:
    """Parse one check module and pull out everything static."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    doc = ast.get_docstring(tree) or ""
    coll = _module_collection_severities(tree) | _data_file_severities(tree)
    findings: list[dict] = []
    seen_keys: set[tuple] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else None)
        if fname != "Finding":
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        sev, resolved = _severity_candidates(kw.get("severity"), tree, coll)
        title = _render_str(kw.get("title"))
        if title is None and kw.get("title") is not None:
            title = _placeholder(kw["title"])
        rem = _render_str(kw.get("remediation"))
        evid = _render_str(kw.get("evidence"))
        row = {
            "sev": sev, "resolved": resolved, "title": title or "",
            "remediation": rem or "", "evidence": evid or "",
        }
        key = (tuple(sorted(sev)), row["title"], row["remediation"], row["evidence"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append(row)
    all_sev = set()
    for f in findings:
        all_sev |= f["sev"]
    return {
        "doc": doc,
        "findings": findings,
        "severity_max": min(all_sev, key=_SEV_RANK.__getitem__) if all_sev else "info",
        "severity_dynamic": any(not f["resolved"] for f in findings),
        "requests": _request_sites(tree),
        "urls": _urls_in(tree),
        "uses_shared": "shared" in path.read_text(encoding="utf-8"),
    }


# ---------------------------------------------------------------------------
# markdown helpers
# ---------------------------------------------------------------------------
def _oneline(text: str) -> str:
    return " ".join(text.split())


def _cell(text: str) -> str:
    """Make text safe inside a markdown table cell (outside code spans: no raw HTML)."""
    text = _oneline(text)
    segs = text.split("`")
    if len(segs) % 2 == 0:  # unbalanced backticks: treat everything as prose
        segs = [text]
        code = False
    else:
        code = True
    out = []
    for i, seg in enumerate(segs):
        seg = seg.replace("|", "\\|")
        if not (code and i % 2 == 1):
            seg = seg.replace("<", "&lt;").replace(">", "&gt;")
        out.append(seg)
    return "`".join(out) if code else out[0]


def _escape_prose(block: str) -> str:
    """Escape raw < and > in prose so <slug> is not swallowed as an HTML tag.

    Code spans, fenced blocks and indented code blocks are left untouched.
    """
    out: list[str] = []
    in_fence = False
    for line in block.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence or line.startswith(("    ", "\t")):
            out.append(line)
            continue
        segs = line.split("`")
        if len(segs) % 2 == 0:  # unbalanced backticks: treat the whole line as prose
            out.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            continue
        fixed = [s.replace("<", "&lt;").replace(">", "&gt;") if i % 2 == 0 else s
                 for i, s in enumerate(segs)]
        out.append("`".join(fixed))
    return "\n".join(out)


def _sev_label(sev: set[str], resolved: bool) -> str:
    ordered = sorted(sev, key=_SEV_RANK.__getitem__)
    if not ordered:
        return "varies"
    if len(ordered) == 1 and resolved:
        return ordered[0]
    return "/".join(ordered) if resolved else "varies (" + ", ".join(ordered) + ")"


def _yaml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def run_command(cid: str, aggressive: bool) -> str:
    """The real single-check invocation: the `only` subcommand (__main__._cmd_only)."""
    cmd = f"wpsecscan only {cid} {EXAMPLE_TARGET}"
    if aggressive:
        cmd += " --aggressive --owned"
    return cmd


def _count_words(prose: list[str]) -> int:
    return sum(len(p.split()) for p in prose)


def build_page(cid: str, display: str, fn, aggressive: bool, category: str) -> tuple[str, dict]:
    """Return (markdown text, meta) for one check."""
    src_file = inspect.getsourcefile(fn)
    info = _analyse(Path(src_file)) if src_file else {
        "doc": "", "findings": [], "severity_max": "info", "severity_dynamic": False, "requests": {}, "urls": [],
        "uses_shared": False}
    tags = _tags_for(cid)
    compliance = _compliance_for(cid)
    # `words` counts only check-specific prose: the docstring, evidence strings and
    # the quick-fix title. Tables, tags, code, headings and the fixed boilerplate
    # sentences below are not counted.
    prose: list[str] = []
    body: list[str] = [f"# {display}", ""]

    body.append(f"**check_id**: `{cid}`")
    body.append(f"**aggressive**: {'yes' if aggressive else 'no'}")
    body.append(f"**category**: {category}")
    body.append(f"**max severity**: {info['severity_max']}"
                + (" (some findings take their severity at run time)" if info["severity_dynamic"] else ""))
    if tags.get("owasp"):
        body.append(f"**OWASP**: {tags['owasp']} — {tags.get('owasp_label', '')}")
    if tags.get("attack"):
        body.append(f"**MITRE ATT&CK**: {tags['attack']} — {tags.get('attack_label', '')}")
    if tags.get("cwe"):
        body.append(f"**CWE**: {tags['cwe']}")
    if tags.get("d3fend"):
        body.append(f"**D3FEND**: {tags['d3fend']}")
    body.append("")

    if info["doc"]:
        body += ["## What it does", "", _escape_prose(info["doc"]), ""]
        prose.append(info["doc"])

    footprint: list[str] = []
    reqs = info["requests"]
    if reqs:
        total = sum(reqs.values())
        parts = ", ".join(f"{m.upper()} x{n}" for m, n in sorted(reqs.items()))
        footprint.append(
            f"The module contains {total} request call(s) to the target ({parts}). "
            "Calls inside loops send more than one request, so treat this as a minimum.")
    if aggressive:
        footprint.append(
            "This is an aggressive check: it sends active probes. It only runs with "
            "--aggressive, and without --owned (or a recorded ownership consent for the "
            "host) the scanner downgrades the run to passive checks only.")
    else:
        footprint.append("This is a passive check: it runs without --aggressive.")
    if footprint:
        body += ["## Request footprint", ""]
        for line in footprint:
            body += [line, ""]

    findings = info["findings"]
    if findings:
        body += ["## Findings this check can raise", "",
                 "| Severity | Finding | Remediation |",
                 "|----------|---------|-------------|"]
        for f in sorted(findings, key=lambda r: (min((_SEV_RANK[s] for s in r["sev"]), default=9), r["title"])):
            body.append(
                f"| {_sev_label(f['sev'], f['resolved'])} | {_cell(f['title'] or '—')} | "
                f"{_cell(f['remediation']) if f['remediation'] else '—'} |")
        body.append("")
        ev = [f for f in findings if f["evidence"]]
        if ev:
            body += ["## Evidence the check records", ""]
            for f in ev:
                line = f"- {f['title'] or 'finding'}: {_oneline(f['evidence'])}"
                body.append(_escape_prose(line))
                prose.append(line)
            body.append("")

    fixes = _load_json("quick_fixes.json")
    qf = (fixes.get("fixes") or {}).get(cid)
    if isinstance(qf, dict) and qf.get("code"):
        body += ["## Suggested fix", ""]
        title = str(qf.get("title", "Fix"))
        intro = f"{title}. Where to apply it: {qf.get('where', 'your site')}."
        body += [intro, "", f"```{qf.get('language', '')}", qf["code"], "```", ""]
        prose.append(title)
    verify = (fixes.get("verify") or {}).get(cid)
    if isinstance(verify, list) and verify:
        lead = "Commands to confirm the issue by hand, and again after you fix it:"
        body += ["## How to verify manually", "", lead, "", "```"]
        body += [str(v).replace("{target}", EXAMPLE_TARGET) for v in verify]
        body += ["```", ""]

    if compliance:
        body += ["## Compliance mapping", ""]
        for src, entry in compliance.items():
            for k, v in entry.items():
                body.append(f"- **{src} / {k}**: {v}")
        body.append("")

    refs: list[str] = []
    ref_entry = (_load_json("references.json")).get(cid)
    if isinstance(ref_entry, dict):
        for label in ("primary", "deep_dive", "video"):
            if ref_entry.get(label):
                refs.append(f"- {label.replace('_', ' ')}: {ref_entry[label]}")
    for url in info["urls"]:
        line = f"- {url}"
        if all(url not in r for r in refs):
            refs.append(line)
    if refs:
        body += ["## References", "", *refs, ""]

    cmd = run_command(cid, aggressive)
    body += ["## Run only this check", "", "```", cmd, "```", ""]
    note = ("`only` runs this check alone and prints its findings. Results that other "
            "checks normally share with it (WAF detection, plugin list, discovered users) "
            "are not populated in that mode.") if info["uses_shared"] else (
            "`only` runs this check alone and prints its findings.")
    body += [note, ""]

    words = _count_words(prose)
    front = ["---",
             f"id: {cid}",
             f"title: {_yaml_str(display)}",
             f"severity_max: {info['severity_max']}",
             f"severity_dynamic: {'true' if info['severity_dynamic'] else 'false'}",
             f"aggressive: {'true' if aggressive else 'false'}",
             f"category: {_yaml_str(category)}",
             f"words: {words}",
             "---", ""]
    meta = {"id": cid, "title": display, "severity_max": info["severity_max"],
            "severity_dynamic": bool(info["severity_dynamic"]),
            "aggressive": bool(aggressive), "category": category, "words": words}
    return "\n".join(front + body), meta


def generate(out_dir: Path, site_checks: Path | None = None) -> list[dict]:
    """Write all pages + README into out_dir; return per-check meta rows."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cat_map, cat_order = _load_categories(site_checks)
    metas: list[dict] = []
    for cid, display, fn, aggressive in ALL_CHECKS:
        category = cat_map.get(cid)
        if not category:
            category = FALLBACK_CATEGORY if cid == "authenticated" else _heuristic_category(cid, display)
        text, meta = build_page(cid, display, fn, aggressive, category)
        (out_dir / f"{cid}.md").write_text(text, encoding="utf-8", newline="\n")
        metas.append(meta)

    # stale pages: ids no longer in the registry
    keep = {m["id"] + ".md" for m in metas} | {"README.md"}
    for p in out_dir.glob("*.md"):
        if p.name not in keep:
            p.unlink()

    for m in metas:
        if m["category"] not in cat_order:
            cat_order.append(m["category"])
    lines = ["# WPSecScan check catalogue", "",
             f"Auto-generated by scripts/generate-docs.py. {len(metas)} checks total.", "",
             "Max severity is the highest severity visible in the check's code. A * marks "
             "checks where some findings take their severity at run time (for example "
             "from CVE data), so the real maximum can be higher.", ""]
    for cat in cat_order:
        rows = [m for m in metas if m["category"] == cat]
        if not rows:
            continue
        lines += [f"## {cat}", "", "| Check ID | Title | Max severity | Aggressive |",
                  "|----------|-------|--------------|------------|"]
        for m in rows:
            lines.append(f"| [`{m['id']}`]({m['id']}.md) | {_cell(m['title'])} | "
                         f"{m['severity_max']}{'*' if m['severity_dynamic'] else ''} | "
                         f"{'yes' if m['aggressive'] else 'no'} |")
        lines.append("")
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return metas


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "checks",
                    help="output directory (default docs/checks)")
    ap.add_argument("--site-checks", type=Path, default=None,
                    help="website src/data/checks.json to copy categories from "
                         "(env: WPSECSCAN_SITE_CHECKS_JSON)")
    args = ap.parse_args(argv)
    site = args.site_checks
    if site is None and os.environ.get("WPSECSCAN_SITE_CHECKS_JSON"):
        site = Path(os.environ["WPSECSCAN_SITE_CHECKS_JSON"])
    metas = generate(args.out, site)
    print(f"wrote {len(metas)} check docs + index to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
