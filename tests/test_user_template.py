"""Wave 3 — tests for wpsecscan/reporters/user_template.py."""
from pathlib import Path

import pytest

from wpsecscan.models import CheckResult, Finding, ScanReport
from wpsecscan.reporters import user_template


def _make():
    return ScanReport(
        target="https://example.com", scanned_at="2026-05-27T00:00:00",
        duration_ms=42,
        results=[CheckResult(check_id="x", check_name="X",
                              findings=[Finding(severity="high", title="bad")])],
    )


def test_render_uses_user_template(tmp_path):
    tpl = tmp_path / "branded.html.j2"
    tpl.write_text(
        "<h1>{{ target }}</h1>"
        "<p>score={{ risk_score }}</p>"
        "<ul>{% for f in findings %}<li>{{ f.severity }}: {{ f.title }}</li>{% endfor %}</ul>",
        encoding="utf-8",
    )
    out = user_template.render(_make(), tpl)
    assert "<h1>https://example.com</h1>" in out
    assert "score=" in out
    assert "<li>high: bad</li>" in out


def test_render_missing_template_raises(tmp_path):
    missing = tmp_path / "nope.html.j2"
    with pytest.raises(FileNotFoundError):
        user_template.render(_make(), missing)


def test_render_autoescape_on_for_html(tmp_path):
    """The target / title are autoescaped — XSS-style strings render safe."""
    tpl = tmp_path / "x.html.j2"
    tpl.write_text("<p>{{ target }}</p>", encoding="utf-8")
    rep = _make()
    rep.target = "<script>alert(1)</script>"
    out = user_template.render(rep, tpl)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_write_produces_file(tmp_path):
    tpl = tmp_path / "x.html.j2"
    tpl.write_text("hi {{ target }}", encoding="utf-8")
    out = tmp_path / "out.html"
    user_template.write(_make(), tpl, out)
    assert "hi https://example.com" in out.read_text(encoding="utf-8")


def test_results_iterable_in_template(tmp_path):
    tpl = tmp_path / "x.html.j2"
    tpl.write_text(
        "{% for r in results %}{{ r.check_id }}={{ r.findings|length }};{% endfor %}",
        encoding="utf-8",
    )
    out = user_template.render(_make(), tpl)
    assert "x=1;" in out


def test_context_includes_now(tmp_path):
    tpl = tmp_path / "x.html.j2"
    tpl.write_text("now={{ now }}", encoding="utf-8")
    out = user_template.render(_make(), tpl)
    assert out.startswith("now=20")  # ISO timestamp starts with the year
