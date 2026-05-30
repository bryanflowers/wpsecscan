"""Coverage for wpsecscan/trust_v27.py.

Pins build_provenance_graph shape, the third_party_audit_url env-var
contract, and set_deterministic_seed side-effects. The reproducible-
build verifier is exercised by patching subprocess.run; we don't
actually pip-download or rebuild a wheel in unit tests.
"""
from __future__ import annotations

import os
import random
from unittest.mock import patch

import pytest

from wpsecscan import trust_v27
from wpsecscan.models import CheckResult, Finding, ScanReport


# ---------------------------------------------------------------------------
# K122 — reproducible_build_verify
# ---------------------------------------------------------------------------

def _fake_completed(returncode=0, stdout="", stderr=""):
    class _R:
        pass
    r = _R()
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = stderr
    return r


def test_reproducible_build_verify_pip_download_failure():
    with patch("subprocess.run",
                return_value=_fake_completed(returncode=1, stderr="network down")):
        ok, msg = trust_v27.reproducible_build_verify("2.7.1")
    assert ok is False
    assert "pip download" in msg


def test_reproducible_build_verify_no_sdist_found(tmp_path, monkeypatch):
    """pip download succeeds (returncode 0) but no sdist lands in the
    work dir → must report 'no sdist found'."""
    monkeypatch.setattr(
        "tempfile.mkdtemp",
        lambda **kw: str(tmp_path),  # noqa: ARG005
    )
    with patch("subprocess.run", return_value=_fake_completed(returncode=0)):
        ok, msg = trust_v27.reproducible_build_verify("2.7.1")
    assert ok is False
    assert "no sdist found" in msg


# ---------------------------------------------------------------------------
# K123 — build_provenance_graph
# ---------------------------------------------------------------------------

def _make_report() -> ScanReport:
    f1 = Finding(severity="high", title="XSS in /search",
                  evidence="<script>", url="https://t/search",
                  extra={"http_method": "POST", "ai_anomaly": 0.92,
                          "kev_match": True, "fp_score": 0.05})
    f2 = Finding(severity="medium", title="info-disclosure", evidence="x")
    r1 = CheckResult(check_id="xss_reflected", check_name="Reflected XSS",
                      findings=[f1, f2])
    return ScanReport(target="https://t", scanned_at="2026-05-27T00:00:00Z",
                       duration_ms=0, results=[r1])


def test_build_provenance_graph_shape():
    rep = _make_report()
    graph = trust_v27.build_provenance_graph(rep)
    assert graph["target"] == "https://t"
    assert graph["scanned_at"] == "2026-05-27T00:00:00Z"
    assert isinstance(graph["lineage"], list)
    assert len(graph["lineage"]) == 2  # two findings


def test_build_provenance_graph_preserves_per_finding_metadata():
    rep = _make_report()
    graph = trust_v27.build_provenance_graph(rep)
    first = graph["lineage"][0]
    assert first["finding_index"] == 0
    assert first["check_id"] == "xss_reflected"
    assert first["severity"] == "high"
    assert first["produced_by_request"]["url"] == "https://t/search"
    assert first["produced_by_request"]["method"] == "POST"
    assert first["policy_applied"]["ai_anomaly"] == 0.92
    assert first["policy_applied"]["kev_match"] is True
    assert first["policy_applied"]["fp_score"] == 0.05


def test_build_provenance_graph_handles_missing_extra():
    """Finding.extra defaults to {}; the helper must fall back to GET
    and emit None for every policy field that wasn't supplied."""
    rep = _make_report()
    second = trust_v27.build_provenance_graph(rep)["lineage"][1]
    assert second["produced_by_request"]["method"] == "GET"
    assert second["produced_by_request"]["url"] == ""
    assert second["policy_applied"]["ai_anomaly"] is None
    assert second["policy_applied"]["kev_match"] is None


def test_build_provenance_graph_empty_report():
    rep = ScanReport(target="https://t", scanned_at="now", duration_ms=0,
                      results=[])
    graph = trust_v27.build_provenance_graph(rep)
    assert graph["lineage"] == []


# ---------------------------------------------------------------------------
# K124 — third_party_audit_url
# ---------------------------------------------------------------------------

def test_third_party_audit_url_empty_by_default(monkeypatch):
    monkeypatch.delenv("WPSECSCAN_AUDIT_URL", raising=False)
    assert trust_v27.third_party_audit_url() == ""


def test_third_party_audit_url_env_override(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_AUDIT_URL", "https://example.com/audit.pdf")
    assert trust_v27.third_party_audit_url() == "https://example.com/audit.pdf"


# ---------------------------------------------------------------------------
# K125 — set_deterministic_seed
# ---------------------------------------------------------------------------

def test_set_deterministic_seed_python_random_reproducible(monkeypatch):
    trust_v27.set_deterministic_seed(42)
    a = [random.random() for _ in range(5)]
    trust_v27.set_deterministic_seed(42)
    b = [random.random() for _ in range(5)]
    assert a == b


def test_set_deterministic_seed_writes_env_var(monkeypatch):
    monkeypatch.delenv("WPSECSCAN_DETERMINISTIC_SEED", raising=False)
    trust_v27.set_deterministic_seed(1337)
    assert os.environ["WPSECSCAN_DETERMINISTIC_SEED"] == "1337"


def test_set_deterministic_seed_default_is_1729(monkeypatch):
    trust_v27.set_deterministic_seed()
    assert os.environ["WPSECSCAN_DETERMINISTIC_SEED"] == "1729"
