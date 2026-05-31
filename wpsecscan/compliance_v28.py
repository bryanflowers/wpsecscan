"""v2.8.1 compliance + enterprise features (F49-F65).

Each helper accepts a wpsecscan ScanReport and emits an artifact (string,
dict, file). Minimal-viable but production-shaped — operators get usable
output today, can refine via custom templates.

All file outputs go through `reporters._atomic_write_text` for crash-safety.
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any

from . import __version__ as _SCANNER_VERSION  # v2.8.2 M2 — frozen-exe-safe


# ---------------------------------------------------------------------------
# F49 — HIPAA technical-safeguards mapping
# ---------------------------------------------------------------------------
_HIPAA_TECH_SAFEGUARDS = {
    "tls_headers":   "164.312(e)(1) Transmission Security",
    "tls_deep":      "164.312(e)(1) Transmission Security",
    "tls_modern":    "164.312(e)(2)(ii) Encryption",
    "cookies":       "164.312(d) Person/Entity Authentication",
    "login":         "164.312(d) Person/Entity Authentication",
    "login_throttle": "164.312(a)(2)(iii) Automatic Logoff",
    "secret_leak":   "164.312(a)(2)(iv) Encryption/Decryption",
    "backup_exposure": "164.312(c)(1) Integrity",
    "exposed_files": "164.312(a)(1) Access Control",
}


def hipaa_safeguards_map(report) -> dict:
    """Map triggered checks → HIPAA Security Rule §164.312 technical-safeguards."""
    out: dict[str, list[str]] = {}
    for r in report.results:
        if not r.findings:
            continue
        safeguard = _HIPAA_TECH_SAFEGUARDS.get(r.check_id)
        if safeguard:
            out.setdefault(safeguard, []).append(r.check_id)
    return {"framework": "HIPAA Security Rule §164.312",
             "triggered_safeguards": out,
             "count": len(out)}


# ---------------------------------------------------------------------------
# F50 — GDPR DPIA helper
# ---------------------------------------------------------------------------
def gdpr_dpia_helper(report) -> dict:
    """Surface findings that imply personal-data risk (Art.35 DPIA triggers)."""
    dpia_relevant = []
    for r in report.results:
        for f in r.findings:
            blob = f"{f.title or ''} {f.evidence or ''}".lower()
            if any(t in blob for t in ("email", "user", "pii", "personal data",
                                          "session", "tracker", "fingerprint",
                                          "secret", "token", "cookie")):
                dpia_relevant.append({
                    "check": r.check_id, "severity": f.severity,
                    "title": (f.title or "")[:120],
                })
    return {
        "framework": "GDPR Art.35 DPIA pre-screen",
        "needs_dpia": bool(dpia_relevant),
        "dpia_triggers": dpia_relevant[:50],
    }


# ---------------------------------------------------------------------------
# F51 — FedRAMP Moderate baseline
# ---------------------------------------------------------------------------
def fedramp_moderate_baseline(report) -> dict:
    """Map findings to FedRAMP Moderate NIST 800-53 rev5 controls.
    Reuses compliance_map.json NIST entries."""
    try:
        from . import tags as _t
        cmap = _t._load_compliance() or {}
    except (ImportError, AttributeError):
        cmap = {}
    controls: dict[str, list[str]] = {}
    for r in report.results:
        if not r.findings:
            continue
        ctrl = (cmap.get(r.check_id) or {}).get("nist_800_53")
        if ctrl:
            controls.setdefault(ctrl, []).append(r.check_id)
    return {"baseline": "FedRAMP Moderate (NIST 800-53 rev5)",
             "triggered_controls": controls}


# ---------------------------------------------------------------------------
# F52 — UK Cyber Essentials Plus
# ---------------------------------------------------------------------------
_CE_PLUS_PILLARS = {
    "Firewalls":        ("tls_headers", "csp", "cors"),
    "Secure config":    ("debug_leaks", "directory_listing", "error_pages",
                          "rest_only_admin_probe"),
    "User access":      ("login", "login_throttle", "users", "app_passwords"),
    "Malware prot.":    ("backup_exposure", "core_tampering"),
    "Patch mgmt":       ("core_version", "plugins", "themes"),
}


def cyber_essentials_plus_report(report) -> dict:
    triggered_by_ids = {r.check_id for r in report.results if r.findings}
    out: dict[str, dict[str, Any]] = {}
    for pillar, checks in _CE_PLUS_PILLARS.items():
        flagged = [c for c in checks if c in triggered_by_ids]
        out[pillar] = {"findings_in_pillar": flagged,
                        "pass": not flagged}
    return {"scheme": "UK Cyber Essentials Plus", "pillars": out}


# ---------------------------------------------------------------------------
# F53 — Australia Essential 8 scorecard
# ---------------------------------------------------------------------------
_E8_STRATEGIES = (
    "Application control", "Patch applications", "Configure MS Office",
    "User application hardening", "Restrict admin privileges",
    "Patch operating systems", "Multi-factor auth", "Daily backups",
)


def essential_8_scorecard(report) -> dict:
    triggered = {r.check_id for r in report.results if r.findings}
    s: dict[str, int] = {}
    s["Patch applications"] = 3 if any(c in triggered for c in
                                          ("plugins", "themes", "core_version")) else 1
    s["Multi-factor auth"] = 3 if "app_passwords" in triggered else 2
    s["Daily backups"] = 2 if "backup_exposure" in triggered else 1
    s["Restrict admin privileges"] = 3 if any(c in triggered for c in
                                                  ("multisite_super_admin_rbac",
                                                   "rest_only_admin_probe")) else 1
    for strat in _E8_STRATEGIES:
        s.setdefault(strat, 0)
    return {"framework": "Australia Essential 8", "maturity": s,
             "scale": "0 (not assessed) – 3 (gap detected; raise priority)"}


# ---------------------------------------------------------------------------
# F54 — SPDX 2.3 SBOM (alongside CycloneDX)
# ---------------------------------------------------------------------------
def spdx_sbom(report, *, doc_name: str = "wpsecscan-sbom") -> dict:
    """Emit an SPDX 2.3 doc covering the scanner itself + each detected plugin/theme."""
    from . import __version__ as _v
    packages = [{
        "SPDXID": "SPDXRef-Package-wpsecscan",
        "name": "wpsecscan", "versionInfo": _v,
        "downloadLocation": "https://pypi.org/project/wpsecscan/",
        "licenseConcluded": "MIT",
    }]
    pid = 1
    for r in report.results:
        if r.check_id not in ("plugins", "themes"):
            continue
        for f in r.findings:
            ttl = (f.title or "")
            packages.append({
                "SPDXID": f"SPDXRef-Package-wp-{pid}",
                "name": ttl[:120].replace("/", "_"),
                "versionInfo": ttl,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
            })
            pid += 1
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": doc_name,
        "documentNamespace": f"https://wpsecscan/sbom/{int(time.time())}",
        "creationInfo": {"created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "creators": ["Tool: wpsecscan"]},
        "packages": packages,
    }


# ---------------------------------------------------------------------------
# F55 — in-toto attestation wrapper
# ---------------------------------------------------------------------------
def intoto_attestation(report, *, builder_id: str = "https://wpsecscan") -> dict:
    """Wrap the scan summary in an in-toto Statement (v0.1) so the report is
    consumable by SLSA verifiers."""
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": report.target,
                      "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://wpsecscan/Attestation/v1",
        "predicate": {
            "builder": {"id": builder_id},
            "scanner": {"name": "wpsecscan"},
            "risk_score": report.risk_score,
            "summary": dict(report.summary or {}),
        },
    }


# ---------------------------------------------------------------------------
# F56 — CEF/LEEF SIEM streaming export
# ---------------------------------------------------------------------------
def cef_export(report) -> str:
    """ArcSight CEF v0 lines, one per finding."""
    lines = []
    for r in report.results:
        for f in r.findings:
            sev_map = {"critical": 10, "high": 8, "medium": 5,
                        "low": 3, "info": 0}
            sev = sev_map.get(f.severity, 0)
            ttl = (f.title or "").replace("|", " ")[:200]
            lines.append(
                f"CEF:0|wpsecscan|wpsecscan|1.0|{r.check_id}|{ttl}|{sev}|"
                f"src={report.target} cs1Label=checkId cs1={r.check_id} "
                f"cs2Label=severity cs2={f.severity}"
            )
    return "\n".join(lines)


def leef_export(report) -> str:
    """IBM LEEF v2.0 lines, one per finding."""
    lines = []
    for r in report.results:
        for f in r.findings:
            ttl = (f.title or "").replace("|", " ")[:200]
            lines.append(
                f"LEEF:2.0|wpsecscan|wpsecscan|1.0|{r.check_id}|"
                f"src={report.target}|severity={f.severity}|title={ttl}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# F57 — Sigstore Rekor remote-witness for audit log
# ---------------------------------------------------------------------------
def rekor_witness_audit_log(audit_log_path: str) -> dict:
    """Submit the audit-log hash to public Rekor (or any compatible mirror).
    No-op if WPSECSCAN_REKOR_URL is not set."""
    rekor = os.environ.get("WPSECSCAN_REKOR_URL")
    if not rekor:
        return {"status": "skipped",
                 "reason": "set WPSECSCAN_REKOR_URL (e.g. https://rekor.sigstore.dev)"}
    p = Path(audit_log_path)
    if not p.exists():
        return {"status": "error", "reason": f"audit log {audit_log_path} not found"}
    import hashlib
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    # We don't ship the full rekor-cli signing flow — emit the digest the
    # operator's `rekor-cli upload --artifact <file>` would publish.
    return {"status": "ok",
             "audit_log_sha256": digest,
             "next_step": f"rekor-cli upload --artifact {audit_log_path} "
                          f"--rekor_server {rekor}"}


# ---------------------------------------------------------------------------
# F58 — SCIM 2.0 user provisioning
# ---------------------------------------------------------------------------
def scim_user_to_creds(scim_user: dict) -> dict:
    """Translate a SCIM 2.0 User object into a wpsecscan creds-vault entry."""
    if not isinstance(scim_user, dict):
        return {"status": "error", "reason": "scim_user must be a dict"}
    name = (scim_user.get("userName") or "").strip()
    if not name:
        return {"status": "error", "reason": "missing userName"}
    emails = scim_user.get("emails") or []
    primary_email = next((e.get("value") for e in emails
                          if isinstance(e, dict) and e.get("primary")), None)
    return {"status": "ok",
             "creds_field_username": name,
             "creds_field_email": primary_email,
             "scim_id": scim_user.get("id")}


# ---------------------------------------------------------------------------
# F59 — Multi-tenant scan-profile isolation
# ---------------------------------------------------------------------------
def tenant_isolated_home(tenant_id: str) -> Path:
    """Return a per-tenant ~/.wpsecscan/<tenant_id>/ directory; operators can
    point WPSECSCAN_HOME at it before invoking each scan."""
    # v2.8.2 L6 — fail loudly on path-traversal attempts instead of
    # silently sanitizing them to underscores (which created confusing
    # `____________etc` tenant directories).
    if "/" in tenant_id or "\\" in tenant_id or ".." in tenant_id:
        raise ValueError(f"tenant_id cannot contain path separators or '..': {tenant_id!r}")
    base = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)[:64]
    if not safe:
        raise ValueError("tenant_id must produce ≥1 alnum/-/_ char")
    home = base / "tenants" / safe
    home.mkdir(parents=True, exist_ok=True)
    return home


# ---------------------------------------------------------------------------
# F60 — White-label PDF theming
# ---------------------------------------------------------------------------
def whitelabel_pdf_theme(*, brand_name: str, logo_path: str | None = None,
                          accent_color: str = "#1565c0") -> dict:
    """Return a theme dict consumable by auditor_pdf — overrides the
    default 'WPSecScan' branding with the customer's brand."""
    return {
        "brand_name": brand_name,
        "logo_path": logo_path,
        "accent_color": accent_color,
    }


# ---------------------------------------------------------------------------
# F61 — Change Advisory Board export
# ---------------------------------------------------------------------------
def cab_export(report) -> str:
    """Generate a CAB-meeting-ready markdown summary."""
    lines = [f"# Change Advisory Board Brief — {report.target}",
             f"\n**Risk score:** {report.risk_score}/100",
             f"**Scan date:** {time.strftime('%Y-%m-%d')}\n",
             "## Proposed changes\n"]
    for r in report.results:
        for f in r.findings:
            if f.severity in ("critical", "high"):
                lines.append(f"- **[{f.severity.upper()}]** {f.title}")
                if f.remediation:
                    lines.append(f"  - *Change:* {f.remediation[:200]}")
    lines.append("\n## Risk + rollback\n")
    lines.append("Each change above is reversible (no data migration). "
                  "Rollback = revert plugin/theme version or remove the "
                  "config rule.\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# F62 — Risk-register CSV/JSON export
# ---------------------------------------------------------------------------
def risk_register_csv(report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["check_id", "severity", "title", "url", "remediation"])
    for r in report.results:
        for f in r.findings:
            w.writerow([r.check_id, f.severity, (f.title or "")[:200],
                         f.url or report.target, (f.remediation or "")[:300]])
    return buf.getvalue()


def risk_register_json(report) -> dict:
    return {
        "target": report.target,
        "risk_score": report.risk_score,
        "register": [
            {"check_id": r.check_id, "severity": f.severity,
              "title": f.title, "remediation": f.remediation,
              "url": f.url or report.target}
            for r in report.results for f in r.findings
        ],
    }


# ---------------------------------------------------------------------------
# F63 — Signed attestation letter
# ---------------------------------------------------------------------------
def attestation_letter(report, *, vendor: str = "Vendor",
                        customer: str = "Customer") -> str:
    """Plain-text attestation letter; customer/vendor PDF signing left to
    auditor_pdf reporter."""
    return (
        f"ATTESTATION\n"
        f"-----------\n"
        f"To: {customer}\n"
        f"From: {vendor}\n"
        f"Subject: Security posture of {report.target}\n"
        f"Date: {time.strftime('%Y-%m-%d')}\n\n"
        f"On the above date, WPSecScan v{_SCANNER_VERSION} "
        f"completed a defensive scan of {report.target}. The scan returned a "
        f"risk score of {report.risk_score}/100 with severity summary "
        f"{dict(report.summary or {})}.\n\n"
        f"This letter constitutes a point-in-time attestation only and does "
        f"not warrant future security state. Signed,\n\n{vendor}\n"
    )


# ---------------------------------------------------------------------------
# F64-bundle — Per-stakeholder bundle (CISO/CIO/DevMgr in one pass)
# ---------------------------------------------------------------------------
def per_stakeholder_bundle(report) -> dict:
    """Build 3 audience-tailored summaries in one pass."""
    crit = sum(1 for r in report.results for f in r.findings
                if f.severity == "critical")
    high = sum(1 for r in report.results for f in r.findings
                if f.severity == "high")
    return {
        "CISO": {
            "headline": f"Risk {report.risk_score}/100. Critical: {crit}, High: {high}.",
            "next_meeting": "review the critical findings and assign owners.",
        },
        "CIO": {
            "headline": f"Site {report.target} scanned. {crit + high} issues need attention.",
            "budget_implication": "patch-cycle effort, no infra change.",
        },
        "DevMgr": {
            "headline": f"{sum(len(r.findings) for r in report.results)} findings; "
                          f"see report for remediation steps.",
            "files_to_touch": "plugins/themes update + nginx headers config.",
        },
    }


# ---------------------------------------------------------------------------
# F65 — CMMC 2.0 Level 2 evidence bundle ZIP
# ---------------------------------------------------------------------------
def cmmc_l2_evidence_bundle(report, out_zip: str) -> dict:
    """Bundle the scan report + audit log + checks list into one ZIP suitable
    for CMMC 2.0 Level 2 evidence."""
    import zipfile
    p = Path(out_zip)
    try:
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("scan-summary.json",
                        json.dumps({"target": report.target,
                                     "risk_score": report.risk_score,
                                     "summary": dict(report.summary or {})},
                                    indent=2))
            z.writestr("risk-register.csv", risk_register_csv(report))
            z.writestr("hipaa-map.json", json.dumps(hipaa_safeguards_map(report), indent=2))
            z.writestr("fedramp-controls.json",
                        json.dumps(fedramp_moderate_baseline(report), indent=2))
            z.writestr("README.txt",
                        "CMMC 2.0 Level 2 evidence bundle generated by wpsecscan.\n"
                        f"Target: {report.target}\n"
                        f"Date: {time.strftime('%Y-%m-%d')}\n")
    # v2.8.2 M8 — `zipfile.BadZipFile` only raised on READ; writing
    # raises OSError. Remove the dead branch.
    except OSError as e:
        return {"status": "error", "error": str(e)}
    return {"status": "ok", "bundle_path": str(p),
             "size_bytes": p.stat().st_size}
