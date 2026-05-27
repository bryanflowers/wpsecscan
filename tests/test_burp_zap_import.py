"""Wave 3 — tests for wpsecscan/importers/burp_zap.py."""
from pathlib import Path

import pytest

from wpsecscan.importers import burp_zap


_BURP_XML = """<?xml version="1.0"?>
<issues>
  <issue>
    <name>SQL injection</name>
    <severity>High</severity>
    <host>https://target.example/</host>
    <path>/?id=</path>
    <issueDetail>POST id=1' AND 1=1-- returned 500</issueDetail>
    <issueBackground>Classic time-based blind</issueBackground>
    <remediationBackground>Use prepared statements</remediationBackground>
  </issue>
  <issue>
    <name>Mixed content</name>
    <severity>Information</severity>
    <host>https://target.example/</host>
    <path>/about</path>
    <issueDetail>http:// image referenced</issueDetail>
  </issue>
</issues>
"""

_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14">
  <site name="https://target.example">
    <alerts>
      <alertitem>
        <alert>X-Frame-Options Header Not Set</alert>
        <riskcode>2</riskcode>
        <desc>Header missing</desc>
        <solution>Add X-Frame-Options: DENY</solution>
        <instances><instance><uri>https://target.example/</uri></instance></instances>
      </alertitem>
      <alertitem>
        <alert>SQL Injection</alert>
        <riskcode>3</riskcode>
        <desc>Param 'id' is vulnerable</desc>
        <solution>Prepared statements</solution>
        <instances><instance><uri>https://target.example/?id=</uri></instance></instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""


def test_burp_import_basic(tmp_path):
    p = tmp_path / "burp.xml"
    p.write_text(_BURP_XML, encoding="utf-8")
    rep = burp_zap.import_burp(p)
    # 2 findings, one synthetic check_id
    findings = rep.all_findings
    assert len(findings) == 2
    assert {f.severity for f in findings} == {"high", "info"}
    assert any(f.title == "SQL injection" for f in findings)
    assert all(f.extra.get("source") == "burp" for f in findings)
    assert rep.target == "https://target.example/"


def test_zap_import_basic(tmp_path):
    p = tmp_path / "zap.xml"
    p.write_text(_ZAP_XML, encoding="utf-8")
    rep = burp_zap.import_zap(p)
    findings = rep.all_findings
    assert len(findings) == 2
    assert {f.severity for f in findings} == {"medium", "high"}
    assert all(f.extra.get("source") == "zap" for f in findings)
    assert "target.example" in rep.target


def test_autoimport_sniffs_zap(tmp_path):
    p = tmp_path / "z.xml"
    p.write_text(_ZAP_XML, encoding="utf-8")
    rep = burp_zap.autoimport(p)
    assert rep.results[0].check_id == "imported_zap"


def test_autoimport_falls_back_to_burp(tmp_path):
    p = tmp_path / "b.xml"
    p.write_text(_BURP_XML, encoding="utf-8")
    rep = burp_zap.autoimport(p)
    assert rep.results[0].check_id == "imported_burp"


def test_target_override(tmp_path):
    p = tmp_path / "b.xml"
    p.write_text(_BURP_XML, encoding="utf-8")
    rep = burp_zap.import_burp(p, target_override="https://override.example")
    assert rep.target == "https://override.example"


def test_burp_severity_mapping(tmp_path):
    """Burp 'Information' must map to wpsecscan 'info'."""
    xml = _BURP_XML.replace("<severity>High</severity>",
                             "<severity>Information</severity>")
    p = tmp_path / "b.xml"
    p.write_text(xml, encoding="utf-8")
    rep = burp_zap.import_burp(p)
    sevs = [f.severity for f in rep.all_findings]
    assert sevs.count("info") == 2  # both findings now map to info


def test_zap_unknown_riskcode_defaults_medium(tmp_path):
    """An unknown ZAP riskcode falls back to medium per _SEV_MAP default."""
    xml = _ZAP_XML.replace("<riskcode>2</riskcode>", "<riskcode>99</riskcode>")
    p = tmp_path / "z.xml"
    p.write_text(xml, encoding="utf-8")
    rep = burp_zap.import_zap(p)
    sevs = [f.severity for f in rep.all_findings]
    assert "medium" in sevs  # the fallback severity
