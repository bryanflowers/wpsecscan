"""Coverage for wpsecscan/edu_v27.py.

Pins the cmd_learn topic dispatcher, translate_report_text no-op
fallbacks, link_glossary_terms regex coverage, confidence_explanation
lookup, plain_language fallback path, and cmd_audio_summary help-out.
"""
from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from wpsecscan import edu_v27


# ---------------------------------------------------------------------------
# J116 — cmd_learn
# ---------------------------------------------------------------------------

def test_cmd_learn_no_args_lists_topics(capsys):
    edu_v27.cmd_learn([])
    out = capsys.readouterr().out
    assert "WPSecScan — learn mode" in out
    # Every topic id should appear in the listing.
    for topic in edu_v27._LEARN_TOPICS:
        assert topic in out


def test_cmd_learn_known_topic_prints_body(capsys):
    edu_v27.cmd_learn(["csp"])
    out = capsys.readouterr().out
    assert "Content-Security-Policy" in out
    assert "CSP" in out


def test_cmd_learn_unknown_topic_exits_64():
    with pytest.raises(SystemExit) as exc:
        edu_v27.cmd_learn(["bogus-topic"])
    assert exc.value.code == 64


# ---------------------------------------------------------------------------
# J117 — translate_report_text
# ---------------------------------------------------------------------------

def test_translate_report_text_empty_returns_empty():
    assert edu_v27.translate_report_text("", "ja") == ""


def test_translate_report_text_english_passthrough():
    assert edu_v27.translate_report_text("hello", "en") == "hello"


def test_translate_report_text_no_ai_backend_passthrough():
    """When ai_assist exists but isn't configured (no API key), the
    helper must return the input verbatim — never silently drop text."""
    with patch("wpsecscan.ai_assist.is_configured", return_value=False):
        assert edu_v27.translate_report_text("hola", "ja") == "hola"


# ---------------------------------------------------------------------------
# J118 — cmd_audio_summary
# ---------------------------------------------------------------------------

def test_cmd_audio_summary_no_args_exits_64(capsys):
    with pytest.raises(SystemExit) as exc:
        edu_v27.cmd_audio_summary([])
    assert exc.value.code == 64
    assert "wpsecscan audio-summary" in capsys.readouterr().err


def test_cmd_audio_summary_help_exits_64(capsys):
    with pytest.raises(SystemExit) as exc:
        edu_v27.cmd_audio_summary(["--help"])
    assert exc.value.code == 64


def test_cmd_audio_summary_no_saved_scan_exits_2(monkeypatch, tmp_path, capsys):
    """When snapshot_history returns [] for the target, the command
    must surface 'no saved scan' and exit 2 — not try to TTS nothing."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    with patch("wpsecscan.history.snapshot_history", return_value=[]):
        with pytest.raises(SystemExit) as exc:
            edu_v27.cmd_audio_summary(["https://example.com"])
    assert exc.value.code == 2
    assert "no saved scan" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# J119 — plain_language
# ---------------------------------------------------------------------------

class _StubFinding:
    title = "stub-title"


def test_plain_language_ai_unavailable_falls_back_to_title():
    """When ai_assist is missing or raises, the helper must return the
    raw finding title — silent-fail must NOT eat the message."""
    with patch("wpsecscan.ai_assist.client_summarize_finding",
                side_effect=AttributeError("not configured")):
        assert edu_v27.plain_language(_StubFinding()) == "stub-title"


# ---------------------------------------------------------------------------
# J120 — link_glossary_terms
# ---------------------------------------------------------------------------

def test_link_glossary_terms_wraps_cve():
    out = edu_v27.link_glossary_terms("see CVE-2024-1234 for details")
    assert "<a href=" in out
    assert "nvd.nist.gov/vuln/detail/CVE-2024-1234" in out
    assert ">CVE-2024-1234</a>" in out


def test_link_glossary_terms_wraps_owasp():
    out = edu_v27.link_glossary_terms("ranked A01:2021 in the top-10")
    assert "owasp.org/Top10" in out
    assert "A01:2021" in out


def test_link_glossary_terms_wraps_attack_technique():
    out = edu_v27.link_glossary_terms("uses T1059.001 PowerShell abuse")
    assert "attack.mitre.org/techniques/T1059.001" in out


def test_link_glossary_terms_wraps_d3fend():
    out = edu_v27.link_glossary_terms("mitigated by D3-DA defenses")
    assert "d3fend.mitre.org" in out
    assert "D3-DA" in out


def test_link_glossary_terms_leaves_plain_text_alone():
    plain = "just a plain string with no tokens"
    assert edu_v27.link_glossary_terms(plain) == plain


# ---------------------------------------------------------------------------
# J121 — confidence_explanation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_confidence_explanation_known_levels(level):
    text = edu_v27.confidence_explanation(level)
    assert text  # non-empty
    assert level in text.lower()


def test_confidence_explanation_normalises_case():
    assert edu_v27.confidence_explanation("HIGH") == edu_v27.confidence_explanation("high")


def test_confidence_explanation_unknown_returns_empty():
    assert edu_v27.confidence_explanation("unknown") == ""
    assert edu_v27.confidence_explanation("") == ""
    assert edu_v27.confidence_explanation(None) == ""  # type: ignore[arg-type]
