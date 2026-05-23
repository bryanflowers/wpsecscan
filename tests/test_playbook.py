"""Exploit playbook loader + safety scan."""
from __future__ import annotations

import json
from pathlib import Path

from wpsecscan import playbook


DATA = json.loads(
    (Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "exploit_playbook.json").read_text(encoding="utf-8")
)
REAL_ENTRIES = {k: v for k, v in DATA.items() if not k.startswith("_") and isinstance(v, dict)}


def test_data_file_parses_and_has_entries():
    assert len(REAL_ENTRIES) >= 20, f"expected ≥20 playbook entries, got {len(REAL_ENTRIES)}"


def test_every_entry_has_how_an_attacker_uses_this():
    """The prose 'why this matters' field is mandatory — it's what makes the
    feature valuable. Lists of commands without context are not useful."""
    missing = [cid for cid, p in REAL_ENTRIES.items() if not p.get("how_an_attacker_uses_this")]
    assert not missing, f"missing how_an_attacker_uses_this: {missing}"


def test_no_destructive_commands():
    """Playbook commands MUST be read-only / probe-only. No DROP TABLE,
    DELETE FROM, INSERT INTO, rm -rf, etc. — even in examples."""
    DANGER = ("DROP TABLE", "DELETE FROM", "TRUNCATE TABLE", "rm -rf /", "INSERT INTO wp_",
              "UPDATE wp_users SET", "ALTER TABLE", "; DROP", "shutdown")
    bad: list[tuple[str, str]] = []
    for cid, p in REAL_ENTRIES.items():
        haystack = json.dumps(p)
        for tok in DANGER:
            if tok.lower() in haystack.lower():
                bad.append((cid, tok))
    assert not bad, f"destructive tokens found: {bad}"


def test_get_playbook_returns_dict_for_known_ids():
    for cid in REAL_ENTRIES:
        pb = playbook.get_playbook(cid)
        assert pb is not None, f"loader missed {cid}"
        assert isinstance(pb, dict)


def test_get_playbook_returns_none_for_unknown():
    assert playbook.get_playbook("definitely-not-a-real-check") is None
    assert playbook.get_playbook("_meta") is None  # documentation, not a check


def test_substitute_replaces_target_and_host():
    raw = {"manual_curl_pocs": ["curl -s {target}/wp-login.php for {host}"]}
    out = playbook.substitute(raw, "https://example.com/")
    assert out["manual_curl_pocs"][0] == "curl -s https://example.com/wp-login.php for example.com"


def test_substitute_handles_trailing_slash_in_target():
    raw = {"manual_curl_pocs": ["curl {target}/x"]}
    out = playbook.substitute(raw, "https://example.com///")
    # Should have exactly one slash between rstripped target and path
    assert "//x" not in out["manual_curl_pocs"][0]
    assert out["manual_curl_pocs"][0].endswith("/x")


def test_substitute_skips_non_string_values():
    raw = {"how_an_attacker_uses_this": "static text", "weird_field": 42}
    out = playbook.substitute(raw, "https://example.com")
    assert out["weird_field"] == 42


def test_ordered_buckets_skips_empty_sections():
    raw = {
        "how_an_attacker_uses_this": "prose",
        "sqlmap": ["cmd"],
        "metasploit": [],   # empty -> skip
        "nuclei": None,     # falsy -> skip
    }
    buckets = playbook.ordered_buckets(raw)
    fields = [f for f, _label, _content in buckets]
    assert "how_an_attacker_uses_this" in fields
    assert "sqlmap" in fields
    assert "metasploit" not in fields
    assert "nuclei" not in fields


def test_ordered_buckets_uses_canonical_order():
    """sqlmap should always come before metasploit, manual_curl_pocs before either."""
    raw = {
        "metasploit": ["a"],
        "sqlmap": ["b"],
        "manual_curl_pocs": ["c"],
        "how_an_attacker_uses_this": "prose",
    }
    fields = [f for f, _label, _content in playbook.ordered_buckets(raw)]
    assert fields.index("how_an_attacker_uses_this") < fields.index("manual_curl_pocs")
    assert fields.index("manual_curl_pocs") < fields.index("sqlmap")
    assert fields.index("sqlmap") < fields.index("metasploit")


def test_html_reporter_passes_playbooks_to_template(tmp_path):
    """End-to-end: a report with a finding for a playbook'd check renders the bucket."""
    from wpsecscan.models import Finding, CheckResult, ScanReport
    from wpsecscan.reporters import html as html_reporter

    r = ScanReport(
        target="https://example.com",
        scanned_at="2026-05-23T00:00:00Z",
        duration_ms=0,
        results=[
            CheckResult(
                check_id="sqli",
                check_name="SQL injection probes",
                findings=[Finding(severity="high", title="Reflected SQLi via ?cat=", evidence="time-based delay")],
            ),
        ],
    )
    rendered = html_reporter.render(r)
    # Header text appears
    assert "How an attacker exploits this" in rendered
    # The sqlmap bucket label
    assert "sqlmap" in rendered.lower()
    # {target} should have been substituted away (no literal '{target}' in output)
    assert "{target}" not in rendered


def test_html_reporter_does_not_render_playbook_for_unknown_check(tmp_path):
    """A check with no playbook entry shouldn't crash and shouldn't render an empty block."""
    from wpsecscan.models import Finding, CheckResult, ScanReport
    from wpsecscan.reporters import html as html_reporter

    r = ScanReport(
        target="https://example.com",
        scanned_at="2026-05-23T00:00:00Z",
        duration_ms=0,
        results=[
            CheckResult(
                check_id="some-check-with-no-playbook",
                check_name="x",
                findings=[Finding(severity="info", title="x", evidence="x")],
            ),
        ],
    )
    rendered = html_reporter.render(r)
    # The page renders fine; no playbook section for the unknown check
    assert "<html" in rendered.lower()
