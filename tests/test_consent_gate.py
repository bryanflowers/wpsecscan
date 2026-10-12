"""v2.9.0 W0b — ownership-consent gate for aggressive scans (offline, no network)."""
from __future__ import annotations

import asyncio

import pytest

from wpsecscan import consent, scanner
from wpsecscan.models import Finding

TARGET = "https://www.example.com/"


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch, tmp_path):
    """Isolated home, no ambient consent, no WAF pre-flight request, no live HTTP."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path / "home"))
    monkeypatch.delenv(consent.ENV_OWNED_TARGETS, raising=False)
    monkeypatch.setenv("WPSECSCAN_OVERRIDE_WAF_DERATE", "1")
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")


@pytest.fixture
def seen(monkeypatch):
    """Replace the check registry with one fake that records ctx['aggressive']."""
    captured: dict = {"aggressive": [], "select_arg": []}

    async def _fake_check(client, ctx):
        captured["aggressive"].append(ctx["aggressive"])
        return []

    def _fake_select(agg, authenticated_enabled=False):
        captured["select_arg"].append(agg)
        return [("fake_check", "Fake check", _fake_check)]

    monkeypatch.setattr(scanner, "select_checks", _fake_select)
    return captured


def _run(target=TARGET, **kw):
    return asyncio.run(scanner.scan(target, timeout=2.0, sequential=True, **kw))


def _gate_findings(report) -> list[Finding]:
    return [f for r in report.results if r.check_id == "consent_gate" for f in r.findings]


# (a) no consent -> downgraded + finding
def test_aggressive_without_consent_is_downgraded_and_recorded(seen):
    report = _run(aggressive=True)
    assert seen["aggressive"] == [False]
    assert seen["select_arg"] == [False]
    gate = _gate_findings(report)
    assert len(gate) == 1
    assert gate[0].severity == "info"
    assert "www.example.com" in gate[0].title
    assert "downgraded to passive" in gate[0].title
    for way in ("--owned", "WPSECSCAN_OWNED_TARGETS", "wpsecscan owned add"):
        assert way in gate[0].evidence


def test_downgrade_also_turns_off_prove(seen):
    report = _run(aggressive=True, prove=True)
    assert seen["aggressive"] == [False]
    assert len(_gate_findings(report)) == 1


# (b) explicit consent
def test_explicit_consent_keeps_aggressive(seen):
    report = _run(aggressive=True, consent=True)
    assert seen["aggressive"] == [True]
    assert _gate_findings(report) == []


# (c) env grants all
@pytest.mark.parametrize("value", ["1", "true", "YES", "*"])
def test_env_all_targets_grants_consent(seen, monkeypatch, value):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, value)
    report = _run(aggressive=True)
    assert seen["aggressive"] == [True]
    assert _gate_findings(report) == []


# (d) env host lists
def test_env_other_host_is_downgraded(seen, monkeypatch):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, "other.example")
    report = _run(aggressive=True)
    assert seen["aggressive"] == [False]
    assert len(_gate_findings(report)) == 1


def test_env_wildcard_matches_subdomain(seen, monkeypatch):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, "*.example.com")
    report = _run(TARGET, aggressive=True)
    assert seen["aggressive"] == [True]
    assert _gate_findings(report) == []


def test_env_wildcard_does_not_match_apex_and_exact_does_not_match_subdomain():
    assert consent.has_consent("https://example.com/", env={consent.ENV_OWNED_TARGETS: "*.example.com"}) is False
    assert consent.has_consent("https://www.example.com/", env={consent.ENV_OWNED_TARGETS: "example.com"}) is False
    assert consent.has_consent("https://EXAMPLE.com/", env={consent.ENV_OWNED_TARGETS: "Example.COM, x.test"}) is True


# (e) owned file
def test_owned_file_grants_consent(seen, tmp_path):
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "owned_targets.json").write_text('{"hosts": ["www.example.com"]}', encoding="utf-8")
    report = _run(aggressive=True)
    assert seen["aggressive"] == [True]
    assert _gate_findings(report) == []


def test_add_and_remove_owned_roundtrip():
    assert consent.load_owned() == set()
    assert consent.add_owned("https://Shop.Example.com:8443/path") == {"shop.example.com"}
    assert consent.has_consent("shop.example.com") is True
    assert consent.remove_owned("shop.example.com") == set()
    assert consent.has_consent("shop.example.com") is False
    with pytest.raises(ValueError):
        consent.add_owned("")


# (f) explicit False beats env
def test_explicit_false_overrides_env(seen, monkeypatch):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, "1")
    report = _run(aggressive=True, consent=False)
    assert seen["aggressive"] == [False]
    assert len(_gate_findings(report)) == 1


# (g) passive scans never carry the finding
@pytest.mark.parametrize("kw", [{}, {"consent": False}, {"consent": True}])
def test_passive_scan_has_no_gate_finding(seen, kw):
    report = _run(aggressive=False, **kw)
    assert seen["aggressive"] == [False]
    assert _gate_findings(report) == []


def test_downgrade_emits_progress_step(seen):
    steps: list[str] = []

    def _cb(event, check_id, name, result):
        if event == "step":
            steps.append(name)

    _run(aggressive=True, on_progress=_cb)
    assert any("downgraded to passive" in s for s in steps)


# (h) corrupt file never raises
@pytest.mark.parametrize("content", ["{not json", "[]", '{"hosts": "example.com"}', '{"hosts": [1, null]}', ""])
def test_corrupt_owned_file_is_treated_as_empty(tmp_path, content):
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "owned_targets.json").write_text(content, encoding="utf-8")
    assert consent.load_owned() == set()
    assert consent.has_consent("https://www.example.com/", env={}) is False


def test_explicit_wins_without_touching_state():
    assert consent.has_consent("x.test", explicit=True, env={}) is True
    assert consent.has_consent("x.test", explicit=False, env={consent.ENV_OWNED_TARGETS: "1"}) is False


# host_of
@pytest.mark.parametrize("raw,expected", [
    ("https://www.Example.com/path?q=1", "www.example.com"),
    ("example.com", "example.com"),
    ("Example.COM", "example.com"),
    ("example.com:8080", "example.com"),
    ("http://user:pw@Example.com:8080/x", "example.com"),
    ("https://example.com./", "example.com"),
    ("http://[::1]:8000/", "::1"),
    ("", ""),
])
def test_host_of(raw, expected):
    assert consent.host_of(raw) == expected
