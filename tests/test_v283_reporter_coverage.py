"""v2.8.3 Phase 3.2 — render+write coverage for 8 of the 14 reporters
that the v2.8.3 audit found had zero dedicated tests.

Pattern: render() with a real-shape report fixture + write() round-trip
through a tmp file, asserting file exists with non-trivial content.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _fixture_report():
    """Minimal but real-shape ScanReport-equivalent for reporter tests."""
    rep = SimpleNamespace(
        target="https://example.com",
        risk_score=58,
        scanned_at="2026-06-01T12:00:00Z",
        duration_ms=12345,
        summary={"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 3},
        results=[
            SimpleNamespace(
                check_id="tls_headers", check_name="TLS headers", error=None,
                findings=[SimpleNamespace(
                    severity="high", title="Missing HSTS",
                    evidence="No Strict-Transport-Security header",
                    remediation="Add `Strict-Transport-Security: max-age=63072000; includeSubDomains`",
                    url="https://example.com", extra={})]),
            SimpleNamespace(
                check_id="csp", check_name="Content Security Policy", error=None,
                findings=[SimpleNamespace(
                    severity="medium", title="Weak CSP",
                    evidence="unsafe-inline present",
                    remediation="Remove unsafe-inline; use nonces",
                    url="https://example.com", extra={"cve": "n/a"})]),
        ],
    )
    rep.worst_severity = lambda: "high"
    # Some reporters access report.all_findings as an iterable shortcut
    rep.all_findings = [f for r in rep.results for f in r.findings]
    return rep


# ===========================================================================
# compliance_attestation (customer-facing — highest priority)
# ===========================================================================
def test_compliance_attestation_render_returns_non_empty():
    from wpsecscan.reporters.compliance_attestation import render
    out = render(_fixture_report())
    assert out  # non-empty
    assert "example.com" in out


def test_compliance_attestation_write_creates_file(tmp_path):
    from wpsecscan.reporters.compliance_attestation import write
    p = tmp_path / "attestation.html"
    write(_fixture_report(), p)
    assert p.exists()
    assert p.stat().st_size > 0


# ===========================================================================
# vex_export (supply-chain VEX format)
# ===========================================================================
def test_vex_export_write_emits_valid_json(tmp_path):
    from wpsecscan.reporters.vex_export import write
    p = tmp_path / "report.vex.json"
    doc = write(_fixture_report(), p)
    assert p.exists()
    re_read = json.loads(p.read_text(encoding="utf-8"))
    assert re_read == doc


# ===========================================================================
# gdpr_dsr_report
# ===========================================================================
def test_gdpr_dsr_report_write_creates_file(tmp_path):
    from wpsecscan.reporters.gdpr_dsr_report import write
    p = tmp_path / "gdpr-dsr.html"
    write(_fixture_report(), p)
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    # Some GDPR-related token must be present.
    assert any(t in body.lower() for t in ("gdpr", "dsr", "data subject", "subject access"))


# ===========================================================================
# auditor_pdf
# ===========================================================================
def test_auditor_pdf_write_creates_file(tmp_path):
    from wpsecscan.reporters.auditor_pdf import write
    p = tmp_path / "auditor.pdf.html"
    write(_fixture_report(), p)
    assert p.exists()
    assert p.stat().st_size > 0


# ===========================================================================
# burp_export
# ===========================================================================
def test_burp_export_write_creates_file(tmp_path):
    from wpsecscan.reporters.burp_export import write
    p = tmp_path / "burp.xml"
    write(_fixture_report(), p)
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    # Should be XML-shaped
    assert body.lstrip().startswith("<")


# ===========================================================================
# finding_heatmap
# ===========================================================================
def test_finding_heatmap_render_svg_returns_svg(tmp_path):
    from wpsecscan.reporters.finding_heatmap import render_svg, write
    svg = render_svg("https://example.com")
    assert "<svg" in svg.lower()
    p = tmp_path / "heatmap.svg"
    write("https://example.com", p)
    assert p.exists()


# ===========================================================================
# executive_tldr
# ===========================================================================
def test_executive_tldr_write_creates_file(tmp_path):
    from wpsecscan.reporters.executive_tldr import write
    p = tmp_path / "tldr.txt"
    write(_fixture_report(), p)
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    # TLDR summarises severity-by-count; doesn't include hostname.
    assert "Posture" in body or "Top items" in body or "high" in body.lower()


# ===========================================================================
# d3fend_mapping
# ===========================================================================
def test_d3fend_mapping_write_creates_file(tmp_path):
    from wpsecscan.reporters.d3fend_mapping import write
    p = tmp_path / "d3fend.html"
    write(_fixture_report(), p)
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    # D3FEND reporter should at minimum render something.
    assert len(body) > 0


# ===========================================================================
# Edge-case: empty-findings report doesn't crash any reporter
# ===========================================================================
def _empty_report():
    rep = SimpleNamespace(
        target="https://clean.example.com",
        risk_score=0,
        scanned_at="2026-06-01T12:00:00Z",
        duration_ms=1234,
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        results=[],
    )
    rep.worst_severity = lambda: "info"
    rep.all_findings = []
    return rep


@pytest.mark.parametrize("reporter_module,write_args", [
    ("compliance_attestation", ()),
    ("gdpr_dsr_report", ()),
    ("auditor_pdf", ()),
    ("burp_export", ()),
    ("executive_tldr", ()),
    ("d3fend_mapping", ()),
])
def test_reporter_handles_empty_findings(tmp_path, reporter_module, write_args):
    """v2.8.3 — every audited reporter must handle a zero-findings report
    without raising. Some reporters (auditor_pdf) intentionally skip
    writing when there's nothing meaningful to report — that's fine."""
    import importlib
    mod = importlib.import_module(f"wpsecscan.reporters.{reporter_module}")
    p = tmp_path / f"{reporter_module}.out"
    # Must not raise. File-existence is best-effort.
    mod.write(_empty_report(), p, *write_args)
