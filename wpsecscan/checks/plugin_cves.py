"""Plugin CVE matching against the Wordfence Intelligence DB.

Uses plugin versions discovered by the `plugins` check (ctx['shared']['plugins']).
When aggressive mode is on, also runs confirmed-exploit signatures from
data/exploit_signatures.json against matching plugins.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from .. import db as vulndb
from ..http import Client
from ..models import Finding


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent.parent / "data"


def _load_signatures() -> list[dict]:
    f = _data_dir() / "exploit_signatures.json"
    sigs: list[dict] = []
    if f.exists():
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            sigs.extend(s for s in (data.get("signatures") or []) if isinstance(s, dict))
        except (OSError, json.JSONDecodeError):
            pass
    # F3: also merge any user-supplied custom signatures from ~/.wpsecscan/signatures/*.json.
    # Each file may be EITHER a list (legacy shape) or a dict with key "signatures" (preferred).
    try:
        import os
        from pathlib import Path as _P
        home = os.environ.get("WPSECSCAN_HOME") or (_P.home() / ".wpsecscan")
        sigs_dir = _P(home) / "signatures"
        if sigs_dir.exists():
            for sf in sorted(sigs_dir.glob("*.json")):
                try:
                    blob = json.loads(sf.read_text(encoding="utf-8"))
                    if isinstance(blob, list):
                        sigs.extend(s for s in blob if isinstance(s, dict))
                    elif isinstance(blob, dict):
                        sigs.extend(s for s in (blob.get("signatures") or []) if isinstance(s, dict))
                except (OSError, json.JSONDecodeError):
                    continue
    except Exception:  # noqa: BLE001
        pass
    return sigs


def _affected_range(vuln: vulndb.Vuln) -> str:
    if vuln.affected_from and vuln.affected_to:
        op = "<=" if vuln.to_inclusive else "<"
        return f"{vuln.affected_from} <= installed {op} {vuln.affected_to}"
    if vuln.affected_to:
        op = "<=" if vuln.to_inclusive else "<"
        return f"installed {op} {vuln.affected_to}"
    if vuln.fixed_in:
        return f"installed < {vuln.fixed_in}"
    return "all versions"


def _next_steps(slug: str, ver: str | None, vuln: vulndb.Vuln) -> list[str]:
    steps: list[str] = []
    if vuln.fixed_in:
        steps.append(f"wp plugin update {slug} --version={vuln.fixed_in}  # via WP-CLI")
    steps.append(f'searchsploit "{slug}"  # check Exploit-DB for public PoCs')
    if "rce" in (vuln.title or "").lower() or "remote code" in (vuln.description or "").lower():
        steps.append(f"# Search Metasploit: `search type:exploit {slug}` in msfconsole")
    return steps


def _dwell_time_note(cve: str) -> tuple[str, int | None]:
    """Estimate attacker dwell-time window from the CVE-YYYY-NNNN year.

    Not exact (CVE-YYYY identifies the YEAR ASSIGNED, not the disclosure
    date), but close enough to convey urgency: a CVE assigned 4 years ago
    has been "publicly known and exploitable since at least YYYY" — every
    day on an unpatched plugin is a day of accumulated risk.

    Returns ("...", years) or ("", None) if no parseable CVE year.
    """
    import re as _re
    m = _re.match(r"CVE-(\d{4})-", cve or "", _re.IGNORECASE)
    if not m:
        return "", None
    year = int(m.group(1))
    from datetime import datetime as _dt
    now_year = _dt.utcnow().year
    yrs = max(0, now_year - year)
    if yrs == 0:
        note = "Publicly known since this year — patch immediately to limit dwell time."
    elif yrs == 1:
        note = f"Publicly known since CVE-{year}-XXX (~1 year of accumulated exposure)."
    else:
        note = f"Publicly known since CVE-{year}-XXX (~{yrs} years of accumulated exposure)."
    return note, yrs


def _vuln_to_finding(slug: str, ver: str | None, vuln: vulndb.Vuln, client: Client) -> Finding:
    refs = "\n".join(f"  - {r}" for r in vuln.references[:5])
    dwell_note, dwell_yrs = _dwell_time_note(vuln.cve)
    evidence = (
        f"{vuln.title}\n"
        f"  Plugin:        {slug}\n"
        f"  Installed:     {ver or 'unknown'}\n"
        f"  Vulnerable:    {_affected_range(vuln)}\n"
        + (f"  Fixed in:      {vuln.fixed_in}\n" if vuln.fixed_in else "")
        + (f"  CVE:           {vuln.cve}\n" if vuln.cve else "")
        + (f"  CVSS:          {vuln.cvss}\n" if vuln.cvss is not None else "")
        + (f"  Dwell time:    {dwell_note}\n" if dwell_note else "")
        + (f"  References:\n{refs}\n" if refs else "")
        + (f"  Description:   {vuln.description[:300]}\n" if vuln.description else "")
    )
    rem = (
        f"Update '{slug}' to {vuln.fixed_in or 'the latest available release'} via Dashboard → Plugins. "
        + (vuln.description if not vuln.fixed_in else "")
    ).strip()
    return Finding(
        severity=vuln.severity,
        title=f"Known vulnerability in {slug} {ver or '(version unknown)'}: {vuln.title[:120]}",
        evidence=evidence,
        remediation=rem,
        url=client.url(f"/wp-content/plugins/{slug}/"),
        extra={
            "cve": vuln.cve,
            "cvss": vuln.cvss,
            "affected_range": _affected_range(vuln),
            "fixed_in": vuln.fixed_in,
            "dwell_years": dwell_yrs,
            "references": vuln.references[:10],
            "next_steps": _next_steps(slug, ver, vuln),
        },
    )


async def _confirm_signature(client: Client, sig: dict) -> dict | None:
    """Run a single exploit signature; return a result dict or None if not matched."""
    method = (sig.get("method") or "GET").upper()
    path = sig.get("path") or "/"
    params = sig.get("params") or None
    body = sig.get("body")
    headers = sig.get("headers") or None
    match = sig.get("match") or "status_eq"
    match_value = sig.get("match_value")

    started = time.perf_counter()
    if method == "GET":
        r = await client.get(path, params=params, headers=headers)
    elif method == "POST":
        kwargs: dict = {}
        if body is not None:
            kwargs["content"] = body
        if headers:
            kwargs["headers"] = headers
        if params:
            kwargs["params"] = params
        r = await client.post(path, **kwargs)
    else:
        return None
    delta = time.perf_counter() - started
    if r is None:
        return None

    ok = False
    detail = ""
    if match == "status_eq":
        ok = r.status_code == match_value
        detail = f"HTTP {r.status_code}"
    elif match == "status_in":
        ok = r.status_code in (match_value or [])
        detail = f"HTTP {r.status_code}"
    elif match == "body_contains":
        ok = isinstance(match_value, str) and (match_value.lower() in (r.text or "").lower())
        detail = f"HTTP {r.status_code}; body match='{match_value}'"
    elif match == "header_contains":
        # match_value is "Header-Name: substring"
        if isinstance(match_value, str) and ":" in match_value:
            hn, _, sub = match_value.partition(":")
            ok = sub.strip().lower() in r.headers.get(hn.strip(), "").lower()
            detail = f"HTTP {r.status_code}; header check"
    elif match == "sleep_delta":
        threshold = float(match_value or 2.5)
        ok = delta >= threshold
        detail = f"HTTP {r.status_code}; delta={delta*1000:.0f} ms (threshold {threshold*1000:.0f})"

    if ok:
        return {"detail": detail, "duration_ms": int(delta * 1000), "status": r.status_code}
    return None


async def _run_sigs_for(
    client: Client,
    sigs: list[dict],
    ver: str | None,
    findings: list[Finding],
    step,
) -> None:
    """Run a set of signatures, gated by max_version when a version is known."""
    for sig in sigs:
        max_v = sig.get("max_version")
        if ver and max_v and not vulndb.ver_lte(ver, max_v):
            continue
        sig_id = sig.get("id", "?")
        step(f"confirming exploit signature {sig_id}...")
        confirmed = await _confirm_signature(client, sig)
        if confirmed:
            findings.append(
                Finding(
                    severity=sig.get("severity", "high"),
                    title="[CONFIRMED] " + (sig.get("title") or f"Exploit signature {sig_id} matched"),
                    evidence=(
                        f"Signature: {sig_id}\n"
                        f"Probe: {sig.get('method','GET')} {sig.get('path')}\n"
                        f"Match: {confirmed['detail']}\n"
                        "This is an actively-confirmed vulnerability, not just a version match."
                    ),
                    remediation=sig.get("remediation", "Update the affected component to the latest release."),
                    url=client.url(sig.get("path", "/")),
                    extra={"signature_id": sig_id},
                )
            )


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    plugins: dict[str, str | None] = ctx.get("shared", {}).get("plugins") or {}

    vulns, age, source = vulndb.load_local()
    if not vulns:
        findings.append(
            Finding(
                severity="info",
                title="Vulnerability database is empty",
                evidence="No cached or embedded vulnerability database found.",
                remediation="Run `wpsecscan --update-db` (CLI) or click 'Refresh DB' in the GUI to download Wordfence Intelligence.",
                url=ctx["target"],
            )
        )
        return findings

    db_note = (
        f"DB source: {source} ({len(vulns)} entries)"
        + (f"; age: {age // 3600} hours" if age >= 0 else "; embedded")
    )

    matched_any = False
    aggressive = bool(ctx.get("aggressive"))
    signatures = _load_signatures() if aggressive else []
    # _section markers are documentation entries in the JSON — never execute them.
    signatures = [s for s in signatures if "_section" not in s and s.get("id")]
    sigs_by_slug: dict[str, list[dict]] = {}
    for s in signatures:
        sigs_by_slug.setdefault((s.get("slug") or "").lower(), []).append(s)

    step = ctx.get("step") or (lambda _s: None)

    if not plugins:
        # No plugins detected — but in aggressive mode we still want to run the
        # ~25 global core/infra probes (wp-cron, install.php, phpinfo, adminer,
        # phpMyAdmin, exposed comment-pingback, etc.) AND any theme-bound sigs.
        findings.append(
            Finding(
                severity="info",
                title="No plugins to cross-reference against CVE database",
                evidence=f"{db_note}. Plugin enumeration found no slugs.",
                remediation="If you know plugins are installed, run against a page that loads them.",
                url=ctx["target"],
            )
        )
        if not aggressive:
            return findings
        # Fall through to the aggressive section below, which runs themes + global probes.
    step(f"cross-referencing {len(plugins)} plugin(s) against {len(vulns)} DB entries...")
    for slug, ver in plugins.items():
        step(f"checking {slug} {ver or '(version unknown)'}...")
        matches = vulndb.find_for(vulns, "plugin", slug, ver)
        if not matches and ver is None:
            # Slug known to DB but no version — surface as low-confidence
            present = any(v.slug == slug.lower() and v.type == "plugin" for v in vulns)
            if present:
                findings.append(
                    Finding(
                        severity="low",
                        title=f"Plugin '{slug}' exists in CVE database but version not detected",
                        evidence=(
                            f"{db_note}. Slug '{slug}' has historical CVEs but no detectable version.\n"
                            "Cannot determine patched status from the outside."
                        ),
                        remediation=f"Manually verify the version of '{slug}' from Dashboard → Plugins. Update to the latest release.",
                        url=client.url(f"/wp-content/plugins/{slug}/"),
                    )
                )
            continue

        for vuln in matches:
            matched_any = True
            findings.append(_vuln_to_finding(slug, ver, vuln, client))
            # Mark this slug as CVE-matched so the plugin_cemetery check can
            # skip it (avoids double-reporting "abandoned + vulnerable" — the
            # CVE finding is already actionable).
            ctx.setdefault("shared", {}).setdefault("cve_matched_slugs", set()).add(slug.lower())

        # Aggressive: run any confirmed-exploit signatures for this slug
        await _run_sigs_for(client, sigs_by_slug.get(slug.lower(), []), ver, findings, step)

    # Aggressive: also iterate THEMES for slug-bound signatures (theme CVEs)
    if aggressive:
        themes: dict[str, str | None] = ctx.get("shared", {}).get("themes") or {}
        for tslug, tver in themes.items():
            sigs = sigs_by_slug.get(tslug.lower(), [])
            if sigs:
                step(f"checking theme signatures for {tslug} {tver or '(version unknown)'}...")
                await _run_sigs_for(client, sigs, tver, findings, step)

        # Run signatures that aren't bound to a specific plugin/theme slug.
        # Three ways a signature opts in:
        #   1. explicit scope == "global" (preferred for new entries)
        #   2. slug starts with "_" (convention for core/infra probes: _core, _global, etc.)
        #      — this catches older entries that pre-date the `scope` field.
        # Without this fallback, ~25 wp-core probes (wp-cron.php, install.php, phpinfo.php,
        # adminer, phpMyAdmin, comment-open, xmlrpc amplifier, etc.) would never fire.
        global_sigs = [
            s for s in signatures
            if s.get("scope") == "global"
            or (s.get("slug") or "").startswith("_")
        ]
        if global_sigs:
            step(f"running {len(global_sigs)} global / core / infra probe(s)...")
            await _run_sigs_for(client, global_sigs, None, findings, step)

    # Optional: cross-reference against WPScan API if a token was provided
    wpscan_token = ctx.get("wpscan_token")
    if wpscan_token and plugins:
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(
                timeout=15.0,
                headers={
                    "Authorization": f"Token token={wpscan_token}",
                    "User-Agent": "WPSecScan/1.0",
                },
            ) as wpc:
                budget = 25  # free tier daily limit; cap per-scan use
                for slug, ver in plugins.items():
                    if budget <= 0 or not ver:
                        continue
                    step(f"WPScan lookup: {slug}...")
                    r = await wpc.get(f"https://wpscan.com/api/v3/plugins/{slug}")
                    budget -= 1
                    if r.status_code == 429:
                        step("WPScan rate-limited; stopping further lookups.")
                        break
                    if r.status_code != 200:
                        continue
                    data = r.json().get(slug) or {}
                    for vu in data.get("vulnerabilities") or []:
                        fixed = vu.get("fixed_in")
                        if not fixed or vulndb.ver_lt(ver, fixed):
                            cve_list = (vu.get("references") or {}).get("cve") or []
                            findings.append(
                                Finding(
                                    severity="high",
                                    title=f"WPScan: {slug} v{ver} — {vu.get('title','vulnerability')}",
                                    evidence=(
                                        f"Source: WPScan API\n"
                                        f"  CVEs: {', '.join(cve_list) or 'n/a'}\n"
                                        f"  Fixed in: {fixed or 'unpatched'}"
                                    ),
                                    remediation=f"Update '{slug}' to {fixed or 'the latest release'}.",
                                    url=client.url(f"/wp-content/plugins/{slug}/"),
                                    extra={"cve": cve_list[0] if cve_list else ""},
                                )
                            )
        except Exception as e:  # noqa: BLE001
            findings.append(
                Finding(
                    severity="info",
                    title="WPScan API lookup failed",
                    evidence=f"{type(e).__name__}: {e}",
                    remediation="Verify --wpscan-token and remaining quota (free tier: 25 req/day).",
                )
            )

    if not matched_any and not any(f.severity in ("critical", "high", "medium") for f in findings):
        findings.append(
            Finding(
                severity="info",
                title=f"No known-vulnerable plugin versions detected among {len(plugins)} plugin(s)",
                evidence=f"{db_note}.",
                remediation="No action needed. Keep all plugins updated — coverage depends on detected versions.",
                url=ctx["target"],
            )
        )

    return findings
